//! Adaptive rate control for the sender (the "SAO" layer of SHARP-256):
//!
//! * [`RttEstimator`] — smoothed RTT and RTO per RFC 6298, a windowed
//!   minimum RTT that adapts when the base delay of the path changes, and
//!   per-round minimum RTTs that tell a standing queue from jitter;
//! * [`Cubic`] — CUBIC congestion control (RFC 8312) in bytes, leaving slow
//!   start through HyStart++ (RFC 9406) and braking in congestion avoidance
//!   while a standing queue persists, so that deep buffers do not turn into
//!   seconds of latency and burst loss;
//! * [`Policer`] — a token-bucket policer recognised by the rate it lets
//!   through, which caps the pacing rate (BBR's long-term bandwidth);
//! * [`Pacer`] — a token bucket that spreads transmissions at the rate the
//!   congestion controller allows.

use std::time::{Duration, Instant};

/// One bucket of the windowed minimum-RTT filter. The minimum is taken over
/// the current and the previous bucket, so a path whose base RTT grew (route
/// change, roaming) is re-learned within one to two buckets.
const MIN_RTT_BUCKET: Duration = Duration::from_secs(10);

/// RTT samples above this are treated as clock trouble and ignored.
const MAX_PLAUSIBLE_RTT: Duration = Duration::from_secs(60);

/// Smoothed RTT / RTO estimator per RFC 6298 with a windowed minimum.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    srtt: Option<Duration>,
    rttvar: Duration,
    latest: Duration,
    cur_min: Duration,
    prev_min: Duration,
    bucket_start: Option<Instant>,
    min_rto: Duration,
    max_rto: Duration,
    /// Longest time the peer may hold back an acknowledgement. RTT samples
    /// exclude it, so the timeout has to add it back (as QUIC's PTO does);
    /// otherwise a very stable path yields a timeout below the time an ACK
    /// can legitimately take.
    max_ack_delay: Duration,
    backoff: u32,
    // Rounds of one smoothed RTT and the smallest sample in each. Jitter
    // moves single samples, not the minimum of a round, so comparing round
    // minimums reveals a standing queue without being fooled by jitter.
    round_start: Option<Instant>,
    round: u64,
    round_min: Duration,
    round_samples: u32,
    last_round_min: Duration,
}

impl RttEstimator {
    pub fn new(min_rto: Duration, max_rto: Duration) -> Self {
        Self {
            srtt: None,
            rttvar: Duration::ZERO,
            latest: Duration::ZERO,
            cur_min: Duration::MAX,
            prev_min: Duration::MAX,
            bucket_start: None,
            min_rto,
            max_rto,
            max_ack_delay: Duration::ZERO,
            backoff: 0,
            round_start: None,
            round: 0,
            round_min: Duration::MAX,
            round_samples: 0,
            last_round_min: Duration::MAX,
        }
    }

    /// Sets the longest time the peer may delay an acknowledgement.
    pub fn set_max_ack_delay(&mut self, delay: Duration) {
        self.max_ack_delay = delay;
    }

    pub fn max_ack_delay(&self) -> Duration {
        self.max_ack_delay
    }

    pub fn on_sample(&mut self, rtt: Duration) {
        self.on_sample_at(rtt, Instant::now());
    }

    pub fn on_sample_at(&mut self, rtt: Duration, now: Instant) {
        if rtt > MAX_PLAUSIBLE_RTT {
            return;
        }
        let rtt = rtt.max(Duration::from_micros(1));
        self.latest = rtt;
        let round_len = self.srtt().max(Duration::from_millis(1));
        match self.round_start {
            Some(start) if now.saturating_duration_since(start) < round_len => {}
            Some(_) => {
                if self.round_samples > 0 {
                    self.last_round_min = self.round_min;
                }
                self.round_min = Duration::MAX;
                self.round_samples = 0;
                self.round_start = Some(now);
                self.round += 1;
            }
            None => self.round_start = Some(now),
        }
        self.round_min = self.round_min.min(rtt);
        self.round_samples += 1;
        match self.bucket_start {
            Some(start) if now.saturating_duration_since(start) < MIN_RTT_BUCKET => {
                self.cur_min = self.cur_min.min(rtt);
            }
            _ => {
                self.prev_min = self.cur_min;
                self.cur_min = rtt;
                self.bucket_start = Some(now);
            }
        }
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(rtt);
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
        self.backoff = 0;
    }

    pub fn has_sample(&self) -> bool {
        self.srtt.is_some()
    }

    /// Smoothed RTT; a conservative default until the first sample arrives.
    pub fn srtt(&self) -> Duration {
        self.srtt.unwrap_or(Duration::from_millis(100))
    }

    /// Minimum RTT over the last one to two filter buckets.
    pub fn min_rtt(&self) -> Duration {
        let m = self.cur_min.min(self.prev_min);
        if m == Duration::MAX {
            self.srtt()
        } else {
            m
        }
    }

    /// Queueing delay that persisted through the whole last round: its
    /// smallest RTT sample above the path minimum. Unlike `SRTT − min_rtt`
    /// this stays at zero on a jittery but uncongested path.
    pub fn standing_queue(&self) -> Duration {
        match self.last_round_min() {
            Some(m) => m.saturating_sub(self.min_rtt()),
            None => Duration::ZERO,
        }
    }

    /// Number of the current round (a round lasts one smoothed RTT).
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Smallest RTT sample of the current round so far.
    pub fn round_min(&self) -> Option<Duration> {
        (self.round_samples > 0).then_some(self.round_min)
    }

    /// Number of RTT samples in the current round so far.
    pub fn round_samples(&self) -> u32 {
        self.round_samples
    }

    /// Smallest RTT sample of the last round that had samples.
    pub fn last_round_min(&self) -> Option<Duration> {
        (self.last_round_min != Duration::MAX).then_some(self.last_round_min)
    }

    pub fn latest(&self) -> Duration {
        self.latest
    }

    /// Retransmission timeout including exponential backoff:
    /// `SRTT + max(4·RTTVAR, 1 ms) + max_ack_delay`, clamped to the bounds.
    pub fn rto(&self) -> Duration {
        let base =
            self.srtt() + (self.rttvar * 4).max(Duration::from_millis(1)) + self.max_ack_delay;
        let base = base.clamp(self.min_rto, self.max_rto);
        let scaled = base.saturating_mul(1u32 << self.backoff.min(6));
        scaled.min(self.max_rto)
    }

    /// The timeout without any backoff: how long an answer should take on
    /// this path as it is measured now.
    pub fn pto(&self) -> Duration {
        let base =
            self.srtt() + (self.rttvar * 4).max(Duration::from_millis(1)) + self.max_ack_delay;
        base.clamp(self.min_rto, self.max_rto)
    }

    pub fn backoff(&mut self) {
        self.backoff = (self.backoff + 1).min(6);
    }

    pub fn reset_backoff(&mut self) {
        self.backoff = 0;
    }
}

/// CUBIC congestion controller (RFC 8312) working in bytes.
#[derive(Debug, Clone)]
pub struct Cubic {
    mss: f64,
    cwnd: f64,
    ssthresh: f64,
    w_max: f64,
    k: f64,
    epoch: Option<Instant>,
    last_loss: Option<Instant>,
    min_cwnd: f64,
    max_cwnd: f64,
    loss_events: u64,
    delay_exits: u64,
    /// Conservative slow start (HyStart++): entered when the minimum RTT of
    /// a round rose, with that minimum as baseline and the round it began.
    css: Option<(Duration, u64)>,
}

const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;

/// Standing queue beyond one base RTT (plus this slack) that freezes window
/// growth in congestion avoidance.
const CA_BRAKE_SLACK: Duration = Duration::from_millis(10);

// HyStart++ (RFC 9406) parameters.
const HYSTART_MIN_THRESH: Duration = Duration::from_millis(4);
const HYSTART_MAX_THRESH: Duration = Duration::from_millis(16);
const HYSTART_MIN_SAMPLES: u32 = 8;
const CSS_GROWTH_DIVISOR: f64 = 4.0;
const CSS_ROUNDS: u64 = 5;

impl Cubic {
    pub fn new(mss: u16, initial_chunks: u32, max_cwnd_bytes: u64) -> Self {
        let mss = mss.max(1) as f64;
        let min_cwnd = 2.0 * mss;
        let max_cwnd = (max_cwnd_bytes as f64).max(min_cwnd * 2.0);
        Self {
            mss,
            cwnd: (initial_chunks.max(2) as f64 * mss).min(max_cwnd),
            ssthresh: max_cwnd,
            w_max: 0.0,
            k: 0.0,
            epoch: None,
            last_loss: None,
            min_cwnd,
            max_cwnd,
            loss_events: 0,
            delay_exits: 0,
            css: None,
        }
    }

    /// Adjusts the segment size after path-MTU probing; keeps the window in bytes.
    pub fn set_mss(&mut self, mss: u16) {
        self.mss = mss.max(1) as f64;
        self.min_cwnd = 2.0 * self.mss;
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    pub fn mss(&self) -> u64 {
        self.mss as u64
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd as u64
    }

    pub fn ssthresh(&self) -> u64 {
        self.ssthresh as u64
    }

    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Whether slow start is in its conservative phase (HyStart++).
    pub fn in_css(&self) -> bool {
        self.css.is_some()
    }

    pub fn loss_events(&self) -> u64 {
        self.loss_events
    }

    /// Number of times slow start ended because of rising delay rather than loss.
    pub fn delay_exits(&self) -> u64 {
        self.delay_exits
    }

    /// HyStart++ (RFC 9406): when the minimum RTT of a round exceeds that of
    /// the previous round by `clamp(min/8, 4 ms, 16 ms)`, a queue is
    /// building and slow start turns conservative (a quarter of the growth).
    /// If a later round's minimum falls below the baseline again, the rise
    /// was jitter and slow start resumes; if it persists for `CSS_ROUNDS`
    /// rounds, slow start ends without having overflowed the buffer.
    fn hystart(&mut self, rtt: &RttEstimator) {
        let enough = rtt.round_samples() >= HYSTART_MIN_SAMPLES;
        match self.css {
            None => {
                let (Some(cur), Some(last)) = (rtt.round_min(), rtt.last_round_min()) else {
                    return;
                };
                let thresh = (last / 8).clamp(HYSTART_MIN_THRESH, HYSTART_MAX_THRESH);
                if enough && cur >= last + thresh {
                    self.css = Some((cur, rtt.round()));
                }
            }
            Some((baseline, start_round)) => {
                if enough && rtt.round_min().is_some_and(|cur| cur < baseline) {
                    self.css = None;
                } else if rtt.round() >= start_round + CSS_ROUNDS {
                    self.css = None;
                    self.ssthresh = self.cwnd;
                    self.delay_exits += 1;
                }
            }
        }
    }

    /// Called with the number of newly acknowledged bytes.
    pub fn on_ack(&mut self, acked: u64, now: Instant, rtt: &RttEstimator) {
        if acked == 0 {
            return;
        }
        if self.cwnd < self.ssthresh {
            self.hystart(rtt);
            if self.cwnd < self.ssthresh {
                let growth = if self.css.is_some() {
                    acked as f64 / CSS_GROWTH_DIVISOR
                } else {
                    acked as f64
                };
                self.cwnd = (self.cwnd + growth).min(self.max_cwnd);
            }
            return;
        }

        // Brake: with a standing queue of more than one base RTT (plus
        // slack) more window only adds latency, so stop growing.
        if rtt.standing_queue() > rtt.min_rtt() + CA_BRAKE_SLACK {
            return;
        }

        let srtt = rtt.srtt();
        let cwnd_seg = self.cwnd / self.mss;
        let acked_seg = acked as f64 / self.mss;
        let epoch = match self.epoch {
            Some(e) => e,
            None => {
                self.epoch = Some(now);
                if self.w_max <= 0.0 {
                    self.w_max = cwnd_seg;
                    self.k = 0.0;
                }
                now
            }
        };
        let rtt_s = srtt.as_secs_f64().max(1e-4);
        let t = now.saturating_duration_since(epoch).as_secs_f64() + rtt_s;
        let target_cubic = CUBIC_C * (t - self.k).powi(3) + self.w_max;
        let target_reno =
            self.w_max * CUBIC_BETA + 3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA) * (t / rtt_s);
        let target = target_cubic.max(target_reno);
        let inc = if target > cwnd_seg {
            (acked_seg * (target - cwnd_seg) / cwnd_seg).min(acked_seg)
        } else {
            acked_seg * 0.01 / cwnd_seg
        };
        self.cwnd = ((cwnd_seg + inc) * self.mss).clamp(self.min_cwnd, self.max_cwnd);
    }

    /// Congestion signal from SACK holes. Returns true if a new loss episode
    /// started (at most one reduction per RTT).
    pub fn on_loss(&mut self, now: Instant, srtt: Duration) -> bool {
        if let Some(t) = self.last_loss {
            if now.saturating_duration_since(t) < srtt {
                return false;
            }
        }
        self.last_loss = Some(now);
        self.loss_events += 1;
        self.css = None;
        let cwnd_seg = self.cwnd / self.mss;
        // Fast convergence (RFC 8312 section 4.6).
        self.w_max = if cwnd_seg < self.w_max {
            cwnd_seg * (1.0 + CUBIC_BETA) / 2.0
        } else {
            cwnd_seg
        };
        let new_seg = (cwnd_seg * CUBIC_BETA).max(2.0);
        self.cwnd = (new_seg * self.mss).clamp(self.min_cwnd, self.max_cwnd);
        self.ssthresh = self.cwnd;
        self.k = (self.w_max * (1.0 - CUBIC_BETA) / CUBIC_C).cbrt();
        self.epoch = Some(now);
        true
    }

    /// Retransmission timeout: collapse the window and restart slow start.
    pub fn on_rto(&mut self, now: Instant) {
        self.loss_events += 1;
        self.css = None;
        let cwnd_seg = self.cwnd / self.mss;
        self.w_max = cwnd_seg.max(2.0);
        // RFC 5681: ssthresh = max(FlightSize/2, 2*SMSS); the loss window is
        // the minimum window, which must stay below ssthresh so that slow
        // start actually restarts.
        self.ssthresh = ((cwnd_seg * CUBIC_BETA).max(4.0) * self.mss).max(self.min_cwnd * 2.0);
        self.cwnd = self.min_cwnd;
        self.k = (self.w_max * (1.0 - CUBIC_BETA) / CUBIC_C).cbrt();
        self.epoch = None;
        self.last_loss = Some(now);
    }

    /// Pacing rate in bytes per second.
    pub fn pacing_rate(&self, srtt: Duration, max_rate: Option<u64>) -> f64 {
        let gain = if self.in_slow_start() && !self.in_css() {
            2.0
        } else {
            1.25
        };
        let rtt = srtt.as_secs_f64().max(1e-4);
        let rate = gain * self.cwnd / rtt;
        let min_rate = 64.0 * self.mss; // never slower than ~64 packets per second
        let rate = rate.max(min_rate);
        match max_rate {
            Some(m) => rate.min(m as f64),
            None => rate,
        }
    }
}

/// A token-bucket policer on the path, recognised by what it lets through
/// (BBR's long-term bandwidth: draft-cardwell-iccrg-bbr-congestion-control,
/// Linux's `tcp_bbr.c`) — and told apart from random loss by what it does
/// when the sender holds to that.
///
/// A policer drops what exceeds its rate at once, without queueing it, so
/// the round-trip time never rises and nothing that waits for a queue
/// brakes. Losses alone do not help a window-based controller either: on a
/// short path its smallest window, two packets a round trip, is far more
/// than a policer of a few hundred kilobytes a second lets through, and the
/// sender sends most of what it sends twice (in the laboratory, 59 to 85
/// per cent; 262 per cent on loopback).
///
/// **Suspected** after two sampling intervals in a row — each of at least
/// [`LT_MIN_ROUNDS`] round trips and [`LT_MIN_TIME`], from a loss on, and
/// ending on one — that each lost at least [`LT_LOSS`] of what they
/// delivered, at delivery rates within an eighth of each other. An
/// interval that goes on for [`LT_MAX_ROUNDS`] and four times
/// [`LT_MIN_TIME`] without losing that much starts the sampling over.
///
/// **Checked**: so does a path that loses a fifth of everything at random,
/// at whatever rate the sender happens to keep (BBR is fooled by it too).
/// The difference is what holding to the rate does: through a policer,
/// sending no faster than it lets through loses next to nothing; random
/// loss goes on as before. So the sender is paced at the mean of the two
/// rates for a check, as long as a sampling interval and [`CHECK_MIN_BYTES`]
/// sent, and if it still loses [`CHECK_LOSS`] or more, at four fifths of it
/// for another (the mean may sit a little above the policer's rate, the
/// bucket's first burst counted in). Losing little at either, it is a
/// policer, held to at that rate; losing as much at both, it is not, and
/// nothing is suspected again for [`QUIET`] (twice as long after each such
/// false alarm in a row). A check counts only what was sent since it began
/// (the sender reports that to [`Policer::on_ack`] while
/// [`Policer::checking_since`] says so, and what it sends to
/// [`Policer::on_sent`]): what went out faster before is still being
/// answered, lost for the most part, when the check begins. On a slow
/// machine, it was most of what a check of fifty milliseconds saw — the
/// sender looked as if it had sent at one and a half times the rate it
/// was held to, and lost a third of it, and a policer of 250 kB/s was let
/// go of as random loss.
///
/// **Held**: [`LT_HOLD_ROUNDS`] round trips and [`LT_HOLD_TIME`] at least.
///
/// **Probed** then, a step at a time: the cap rises by [`PROBE_GAIN`] every
/// [`LT_MIN_ROUNDS`] round trips and [`PROBE_STEP`], and is lifted once it
/// is [`PROBE_LIMIT`] times the rate held to. A policer that is still there
/// is suspected again at the first step and checked; one that is gone is
/// left behind in a few seconds. (Lifting the cap at once would let the
/// window-based controller overrun it again at its full rate.)
#[derive(Debug, Clone, Default)]
pub struct Policer {
    /// The interval being sampled: when and in which round it began, and
    /// what was delivered and lost since.
    sampling: Option<(Instant, u64, u64, u64)>,
    /// The delivery rate of the previous lossy interval, bytes a second.
    last: Option<f64>,
    state: PolicerState,
    /// Nothing is suspected before this, and how many false alarms in a row
    /// have put it off.
    quiet_until: Option<Instant>,
    false_alarms: u32,
    detections: u64,
}

#[derive(Debug, Clone, Copy, Default)]
enum PolicerState {
    #[default]
    Free,
    /// Paced at `rate` since `since`, round `round`, to see what is lost
    /// at it: `sent` since, and `delivered` and `lost` of that; `lowered`
    /// once it is four fifths of the rate suspected.
    Checking {
        rate: f64,
        lowered: bool,
        since: Instant,
        round: u64,
        delivered: u64,
        lost: u64,
        sent: u64,
    },
    /// Paced at `rate` since `since`, round `round`.
    Held {
        rate: f64,
        since: Instant,
        round: u64,
    },
    /// Paced at `cap`, raised last at `since`, round `round`, from `base`.
    Probing {
        base: f64,
        cap: f64,
        since: Instant,
        round: u64,
    },
}

pub const LT_MIN_ROUNDS: u64 = 4;
pub const LT_MIN_TIME: Duration = Duration::from_millis(50);
pub const LT_MAX_ROUNDS: u64 = 16;
/// Lost over delivered (BBR's 50/256).
pub const LT_LOSS: f64 = 0.2;
/// Lost over delivered, held to the rate suspected, that says the path is
/// no policer.
pub const CHECK_LOSS: f64 = 0.1;
/// What a check has to have sent at, as a share of the rate checked, to say
/// anything.
pub const CHECK_REACH: f64 = 0.7;
/// What a check has to have seen answered, delivered or lost, to say
/// anything: two dozen full datagrams.
pub const CHECK_MIN_BYTES: u64 = 32 * 1024;
pub const LT_HOLD_ROUNDS: u64 = 48;
pub const LT_HOLD_TIME: Duration = Duration::from_secs(2);
pub const PROBE_GAIN: f64 = 1.25;
pub const PROBE_STEP: Duration = Duration::from_millis(200);
pub const PROBE_LIMIT: f64 = 16.0;
/// How long nothing is suspected after a false alarm, doubled for each one
/// in a row, up to [`QUIET_MAX`].
pub const QUIET: Duration = Duration::from_secs(30);
pub const QUIET_MAX: Duration = Duration::from_secs(600);

impl Policer {
    /// Takes what an acknowledgement delivered and what it showed lost, in
    /// bytes, in round `round` of the [`RttEstimator`]. Returns the rate,
    /// when this is what made a policer known (checked).
    pub fn on_ack(&mut self, now: Instant, round: u64, delivered: u64, lost: u64) -> Option<f64> {
        self.advance(now, round);
        if let PolicerState::Checking { .. } = self.state {
            return self.check(now, round, delivered, lost);
        }
        if matches!(self.state, PolicerState::Held { .. })
            || self.quiet_until.is_some_and(|q| now < q)
        {
            return None;
        }
        let Some((start, start_round, mut got, mut gone)) = self.sampling else {
            // Sampling begins at a loss.
            if lost > 0 {
                self.sampling = Some((now, round, 0, lost));
            }
            return None;
        };
        got += delivered;
        gone += lost;
        self.sampling = Some((start, start_round, got, gone));
        let rounds = round.saturating_sub(start_round);
        let took = now.saturating_duration_since(start);
        if rounds > LT_MAX_ROUNDS && took > 4 * LT_MIN_TIME {
            self.sampling = None;
            self.last = None;
            return None;
        }
        if lost == 0 || rounds < LT_MIN_ROUNDS || took < LT_MIN_TIME {
            return None;
        }
        if (gone as f64) < LT_LOSS * got as f64 {
            return None;
        }
        let rate = got as f64 / took.as_secs_f64();
        match self.last {
            Some(last) if (rate - last).abs() <= last / 8.0 => {
                self.sampling = None;
                self.last = None;
                self.state = PolicerState::Checking {
                    rate: (rate + last) / 2.0,
                    lowered: false,
                    since: now,
                    round,
                    delivered: 0,
                    lost: 0,
                    sent: 0,
                };
                None
            }
            _ => {
                self.last = Some(rate);
                self.sampling = Some((now, round, 0, 0));
                None
            }
        }
    }

    /// A check under way: what is lost at the rate held to.
    fn check(&mut self, now: Instant, round: u64, got: u64, gone: u64) -> Option<f64> {
        let PolicerState::Checking {
            rate,
            lowered,
            since,
            round: from,
            delivered,
            lost,
            sent,
        } = self.state
        else {
            return None;
        };
        let (delivered, lost) = (delivered + got, lost + gone);
        // Long enough to say something.
        if round < from + LT_MIN_ROUNDS
            || now.saturating_duration_since(since) < LT_MIN_TIME
            || delivered + lost < CHECK_MIN_BYTES
            || delivered == 0
        {
            self.state = PolicerState::Checking {
                rate,
                lowered,
                since,
                round: from,
                delivered,
                lost,
                sent,
            };
            return None;
        }
        // A sender that did not even come up to the rate — held back by its
        // window, or by what it has to send — says nothing of what the path
        // does at it: little lost then is no policer's doing, and a cap it
        // does not reach is no use. (A window shrunk by random loss was
        // taken for a policer's verdict so.)
        let offered = sent as f64 / now.saturating_duration_since(since).as_secs_f64();
        if offered < CHECK_REACH * rate {
            self.state = PolicerState::Free;
            return None;
        }
        if (lost as f64) < CHECK_LOSS * delivered as f64 {
            // Little lost where the path was held to: a policer.
            self.state = PolicerState::Held {
                rate,
                since: now,
                round,
            };
            self.detections += 1;
            self.false_alarms = 0;
            return Some(rate);
        }
        if !lowered {
            self.state = PolicerState::Checking {
                rate: rate * 0.8,
                lowered: true,
                since: now,
                round,
                delivered: 0,
                lost: 0,
                sent: 0,
            };
            return None;
        }
        // As much lost at four fifths of the rate: random loss, which no
        // pace avoids. Nothing is suspected for a while.
        self.false_alarms += 1;
        let quiet = QUIET
            .saturating_mul(1 << (self.false_alarms - 1).min(5))
            .min(QUIET_MAX);
        self.quiet_until = Some(now + quiet);
        self.state = PolicerState::Free;
        None
    }

    /// Moves from holding to probing, and the probe a step up, when due.
    fn advance(&mut self, now: Instant, round: u64) {
        match self.state {
            PolicerState::Free | PolicerState::Checking { .. } => {}
            PolicerState::Held {
                rate,
                since,
                round: from,
            } => {
                if round >= from + LT_HOLD_ROUNDS
                    && now.saturating_duration_since(since) >= LT_HOLD_TIME
                {
                    self.state = PolicerState::Probing {
                        base: rate,
                        cap: rate * PROBE_GAIN,
                        since: now,
                        round,
                    };
                }
            }
            PolicerState::Probing {
                base,
                cap,
                since,
                round: from,
            } => {
                if round >= from + LT_MIN_ROUNDS
                    && now.saturating_duration_since(since) >= PROBE_STEP
                {
                    let cap = cap * PROBE_GAIN;
                    self.state = if cap > base * PROBE_LIMIT {
                        PolicerState::Free
                    } else {
                        PolicerState::Probing {
                            base,
                            cap,
                            since: now,
                            round,
                        }
                    };
                }
            }
        }
    }

    /// Takes what the sender sent, in bytes: a check measures how fast.
    pub fn on_sent(&mut self, bytes: u64) {
        if let PolicerState::Checking { sent, .. } = &mut self.state {
            *sent += bytes;
        }
    }

    /// When the check under way began, if one is: [`on_ack`](Self::on_ack)
    /// is then to be told only of what was sent since.
    pub fn checking_since(&self) -> Option<Instant> {
        match self.state {
            PolicerState::Checking { since, .. } => Some(since),
            _ => None,
        }
    }

    /// The pacing rate's cap in bytes a second: the rate being checked or
    /// held to, the probe's after.
    pub fn rate(&self) -> Option<f64> {
        match self.state {
            PolicerState::Free => None,
            PolicerState::Checking { rate, .. } | PolicerState::Held { rate, .. } => Some(rate),
            PolicerState::Probing { cap, .. } => Some(cap),
        }
    }

    /// Whether a policer's rate is being held to (checked).
    pub fn holding(&self) -> bool {
        matches!(self.state, PolicerState::Held { .. })
    }

    /// Whether a policer has been found and not let go of: held to, or
    /// probed above — what makes UDP suspect for a trial on a stream.
    pub fn found(&self) -> bool {
        matches!(
            self.state,
            PolicerState::Held { .. } | PolicerState::Probing { .. }
        )
    }

    /// How many times a policer was found (checked).
    pub fn detections(&self) -> u64 {
        self.detections
    }

    /// Forgets everything but the count: the path changed.
    pub fn reset(&mut self) {
        *self = Self {
            detections: self.detections,
            ..Self::default()
        };
    }
}

/// Token-bucket pacer: smooths transmission to the configured rate while
/// permitting bounded bursts (important because timers are ~1 ms coarse).
#[derive(Debug, Clone)]
pub struct Pacer {
    rate: f64,
    tokens: f64,
    burst: f64,
    last: Instant,
}

impl Pacer {
    pub fn new(now: Instant, rate: f64, burst: f64) -> Self {
        Self {
            rate: rate.max(1.0),
            tokens: burst,
            burst: burst.max(1.0),
            last: now,
        }
    }

    pub fn set_rate(&mut self, rate: f64) {
        self.rate = rate.max(1.0);
    }

    pub fn set_burst(&mut self, burst: f64) {
        self.burst = burst.max(1.0);
        self.tokens = self.tokens.min(self.burst);
    }

    pub fn rate(&self) -> f64 {
        self.rate
    }

    pub fn burst(&self) -> f64 {
        self.burst
    }

    pub fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
    }

    /// Consumes `bytes` if available.
    pub fn try_take(&mut self, bytes: u64) -> bool {
        let b = bytes as f64;
        if self.tokens >= b {
            self.tokens -= b;
            true
        } else {
            false
        }
    }

    /// Returns tokens taken for a datagram that was not actually sent.
    pub fn refund(&mut self, bytes: u64) {
        self.tokens = (self.tokens + bytes as f64).min(self.burst);
    }

    /// Time until `bytes` tokens will be available.
    pub fn delay_for(&self, bytes: u64) -> Duration {
        let missing = bytes as f64 - self.tokens;
        if missing <= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(missing / self.rate)
        }
    }
}

/// Burst allowance for a given pacing rate: 1 ms worth of data (the timer
/// granularity; a sender that sends in segmented batches emits a burst in
/// microseconds, and longer bursts overrun shallow buffers on the path), at
/// least 16 chunks, at most 1024 chunks.
pub fn burst_for_rate(rate: f64, chunk: u16) -> f64 {
    let chunk = chunk.max(1) as f64;
    (rate * 0.001).clamp(16.0 * chunk, 1024.0 * chunk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn est() -> RttEstimator {
        RttEstimator::new(Duration::from_millis(50), Duration::from_secs(10))
    }

    /// Feeds one round of RTT samples (in ms) at `t`, then moves `t` past the
    /// end of that round so that the next sample starts a new one.
    fn feed_round(e: &mut RttEstimator, t: &mut Instant, samples_ms: &[u64]) {
        let before = e.srtt();
        for &ms in samples_ms {
            e.on_sample_at(Duration::from_millis(ms), *t);
        }
        *t += before.max(e.srtt()) + Duration::from_millis(1);
    }

    #[test]
    fn rtt_estimator_follows_rfc6298() {
        let mut e = est();
        assert!(!e.has_sample());
        assert_eq!(e.srtt(), Duration::from_millis(100));
        e.on_sample(Duration::from_millis(100));
        assert_eq!(e.srtt(), Duration::from_millis(100));
        assert_eq!(e.rto(), Duration::from_millis(300)); // 100 + 4*50
        e.on_sample(Duration::from_millis(100));
        e.on_sample(Duration::from_millis(100));
        assert!(e.rto() < Duration::from_millis(300));
        e.backoff();
        let r1 = e.rto();
        e.backoff();
        assert!(e.rto() > r1);
        e.on_sample(Duration::from_millis(1));
        assert!(e.rto() >= Duration::from_millis(50)); // min_rto respected
        assert_eq!(e.min_rtt(), Duration::from_millis(1));
        e.on_sample(Duration::from_secs(120)); // rejected
        assert!(e.latest() < Duration::from_secs(120));
    }

    #[test]
    fn rto_covers_the_peers_ack_delay() {
        let mut e = RttEstimator::new(Duration::from_millis(10), Duration::from_secs(10));
        e.set_max_ack_delay(Duration::from_millis(20));
        for _ in 0..60 {
            e.on_sample(Duration::from_millis(100)); // perfectly stable path
        }
        // 100 ms + 1 ms variance floor + 20 ms the peer may hold an ACK.
        assert!(e.rto() >= Duration::from_millis(121), "{:?}", e.rto());
        assert!(e.rto() < Duration::from_millis(125), "{:?}", e.rto());
    }

    #[test]
    fn windowed_min_rtt_adapts_to_a_slower_path() {
        let t0 = Instant::now();
        let mut e = est();
        e.on_sample_at(Duration::from_millis(10), t0);
        e.on_sample_at(Duration::from_millis(12), t0 + Duration::from_secs(1));
        assert_eq!(e.min_rtt(), Duration::from_millis(10));
        // Route change: base RTT is now 50 ms.
        e.on_sample_at(Duration::from_millis(50), t0 + Duration::from_secs(11));
        assert_eq!(e.min_rtt(), Duration::from_millis(10)); // previous bucket still counts
        e.on_sample_at(Duration::from_millis(51), t0 + Duration::from_secs(22));
        assert_eq!(e.min_rtt(), Duration::from_millis(50)); // old minimum expired
    }

    #[test]
    fn cubic_slow_start_then_backoff_on_loss() {
        let now = Instant::now();
        let mut e = est();
        e.on_sample(Duration::from_millis(50));
        let mut c = Cubic::new(1432, 10, 64 << 20);
        let start = c.cwnd();
        assert!(c.in_slow_start());
        c.on_ack(1432 * 10, now, &e);
        assert_eq!(c.cwnd(), start * 2);
        let before = c.cwnd();
        assert!(c.on_loss(now, Duration::from_millis(50)));
        assert!(c.cwnd() < before);
        assert!(!c.in_slow_start());
        // Second loss inside one RTT is ignored.
        assert!(!c.on_loss(now + Duration::from_millis(10), Duration::from_millis(50)));
        // After the loss the window grows again in congestion avoidance.
        let after_loss = c.cwnd();
        let mut t = now + Duration::from_millis(60);
        for _ in 0..200 {
            c.on_ack(1432 * 4, t, &e);
            t += Duration::from_millis(10);
        }
        assert!(c.cwnd() > after_loss);
        assert!(c.cwnd() <= 64 << 20);
        // Never below two segments even after many RTOs.
        for _ in 0..10 {
            c.on_rto(t);
        }
        assert_eq!(c.cwnd(), 2 * 1432);
        assert!(c.in_slow_start());
        assert!(c.loss_events() >= 11);
    }

    #[test]
    fn hystart_leaves_slow_start_on_a_standing_queue() {
        let mut t = Instant::now();
        let mut e = est();
        let mut c = Cubic::new(1000, 10, 1 << 30);
        for _ in 0..3 {
            feed_round(&mut e, &mut t, &[20; 10]);
            c.on_ack(1000, t, &e);
        }
        assert!(c.in_slow_start() && !c.in_css());
        // A queue builds: the minimum of a whole round rises by 30 ms.
        feed_round(&mut e, &mut t, &[50; 10]);
        c.on_ack(1000, t, &e);
        assert!(
            c.in_css(),
            "a rising round minimum starts conservative slow start"
        );
        let w = c.cwnd();
        c.on_ack(4000, t, &e);
        assert_eq!(c.cwnd(), w + 1000, "a quarter of the slow-start growth");
        // The queue persists for CSS_ROUNDS rounds: slow start ends.
        for _ in 0..CSS_ROUNDS {
            feed_round(&mut e, &mut t, &[50; 10]);
            c.on_ack(1000, t, &e);
        }
        assert!(!c.in_slow_start() && !c.in_css());
        assert_eq!(c.delay_exits(), 1);
    }

    #[test]
    fn hystart_resumes_slow_start_after_a_passing_delay() {
        let mut t = Instant::now();
        let mut e = est();
        let mut c = Cubic::new(1000, 10, 1 << 30);
        for _ in 0..3 {
            feed_round(&mut e, &mut t, &[20; 10]);
            c.on_ack(1000, t, &e);
        }
        feed_round(&mut e, &mut t, &[50; 10]);
        c.on_ack(1000, t, &e);
        assert!(c.in_css());
        // The next round's minimum is back below the baseline: it was not a
        // standing queue, so slow start continues at full speed.
        feed_round(&mut e, &mut t, &[21; 10]);
        c.on_ack(1000, t, &e);
        assert!(c.in_slow_start() && !c.in_css());
        let w = c.cwnd();
        c.on_ack(4000, t, &e);
        assert_eq!(c.cwnd(), w + 4000);
        assert_eq!(c.delay_exits(), 0);
    }

    #[test]
    fn jitter_alone_never_ends_slow_start() {
        // Wi-Fi-like path: base RTT 20 ms, samples scattered up to 45 ms. The
        // smoothed RTT sits ~10 ms above the minimum, but every round still
        // contains a sample near the base RTT.
        let mut t = Instant::now();
        let mut e = est();
        let mut c = Cubic::new(1000, 10, 1 << 30);
        for _ in 0..20 {
            feed_round(&mut e, &mut t, &[20, 35, 28, 45, 21, 33, 25, 40, 30, 38]);
            c.on_ack(1000, t, &e);
            assert!(!c.in_css());
        }
        assert!(e.srtt() > e.min_rtt() + Duration::from_millis(5));
        assert!(c.in_slow_start());
        assert_eq!(e.standing_queue(), Duration::ZERO);
    }

    #[test]
    fn congestion_avoidance_freezes_under_a_standing_queue() {
        let mut t = Instant::now();
        let mut e = est();
        feed_round(&mut e, &mut t, &[10; 10]);
        let mut c = Cubic::new(1000, 100, 1 << 30);
        assert!(c.on_loss(t, Duration::from_millis(10))); // enter CA
        for _ in 0..3 {
            feed_round(&mut e, &mut t, &[80; 10]); // standing queue ~70 ms > 10 + 10
        }
        let w = c.cwnd();
        for _ in 0..100 {
            c.on_ack(4000, t, &e);
            t += Duration::from_millis(5);
        }
        assert_eq!(c.cwnd(), w, "window must not grow while the queue is deep");
        // The queue drains; what remains is jitter, which must not brake.
        for _ in 0..3 {
            feed_round(&mut e, &mut t, &[11, 60, 30, 45, 11, 70, 25, 50, 12, 65]);
        }
        for _ in 0..100 {
            c.on_ack(4000, t, &e);
            t += Duration::from_millis(5);
        }
        assert!(c.cwnd() > w);
    }

    /// A sender far faster than a 250 kB/s policer on a path with a round
    /// trip of a millisecond, acknowledged every millisecond: what it
    /// sends beyond the policer's rate is lost.
    fn policed(p: &mut Policer, t: &mut Instant, round: &mut u64, ms: u64, offered: f64) {
        let rate = 250_000.0;
        for _ in 0..ms {
            *t += Duration::from_millis(1);
            *round += 1;
            let cap = p.rate().unwrap_or(f64::MAX).min(offered);
            let sent = cap / 1000.0;
            let got = sent.min(rate / 1000.0);
            p.on_sent(sent as u64);
            p.on_ack(*t, *round, got as u64, (sent - got) as u64);
        }
    }

    #[test]
    fn a_policer_is_found_at_its_rate_and_held_to() {
        let mut p = Policer::default();
        let (mut t, mut round) = (Instant::now(), 0);
        policed(&mut p, &mut t, &mut round, 300, 10e6);
        let rate = p.rate().expect("found");
        assert!((rate - 250_000.0).abs() < 250_000.0 / 16.0, "{}", rate);
        assert!(p.holding());
        assert_eq!(p.detections(), 1);
        // Held to: nothing lost meanwhile, and the cap stays.
        policed(&mut p, &mut t, &mut round, 1500, 10e6);
        assert_eq!(p.rate(), Some(rate));
    }

    #[test]
    fn a_policer_still_there_is_found_again_at_the_first_step() {
        let mut p = Policer::default();
        let (mut t, mut round) = (Instant::now(), 0);
        policed(&mut p, &mut t, &mut round, 300, 10e6);
        let rate = p.rate().unwrap();
        // The hold runs out after two seconds...
        let mut held = 0;
        while p.holding() {
            policed(&mut p, &mut t, &mut round, 1, 10e6);
            held += 1;
        }
        assert!((1700..2300).contains(&held), "{} ms", held);
        // ...the probe goes a quarter higher, loses a fifth of it, and the
        // policer is found again before the next step.
        assert!(p.rate().unwrap() > rate * 1.2);
        let mut probed = 0;
        while !p.holding() {
            policed(&mut p, &mut t, &mut round, 1, 10e6);
            probed += 1;
        }
        assert!(probed < 400, "{} ms", probed);
        assert_eq!(p.detections(), 2);
    }

    #[test]
    fn a_policer_gone_is_left_behind_a_step_at_a_time() {
        let mut p = Policer::default();
        let (mut t, mut round) = (Instant::now(), 0);
        policed(&mut p, &mut t, &mut round, 300, 10e6);
        let rate = p.rate().unwrap();
        // The policer is lifted: nothing is lost any more.
        let mut caps = vec![];
        for _ in 0..80 {
            t += Duration::from_millis(100);
            round += 100;
            p.on_ack(t, round, 1000, 0);
            caps.push(p.rate());
        }
        assert!(caps.windows(2).all(|w| match (w[0], w[1]) {
            (Some(a), Some(b)) => b >= a && b <= a * 1.25 + 1.0,
            (_, None) => true,
            (None, Some(_)) => false,
        }));
        assert_eq!(p.rate(), None, "lifted after {:?}", caps);
        assert!(caps.contains(&Some(rate)));
    }

    /// A fifth of everything lost at random, whatever is sent, by a sender
    /// that keeps a steady rate — which looks like a policer to the
    /// sampling (as it does to BBR's): checked, losing as much held to the
    /// rate as before, it is let go of, and not suspected again for a while.
    /// (Before the check, a "lower rate found" replaced the one held to,
    /// four fifths at a time: 0.8 Mbit/s on a 50 Mbit/s path in the
    /// laboratory of bad networks.)
    #[test]
    fn steady_random_loss_is_checked_and_let_go_of() {
        let mut p = Policer::default();
        let (mut t, mut round) = (Instant::now(), 0);
        let mut capped_ms = 0;
        for _ in 0..10_000 {
            t += Duration::from_millis(1);
            round += 1;
            let sent = p.rate().unwrap_or(f64::MAX).min(4e6) / 1000.0;
            p.on_sent(sent as u64);
            p.on_ack(t, round, (sent * 0.8) as u64, (sent * 0.2) as u64);
            capped_ms += p.rate().is_some() as u32;
        }
        assert_eq!(p.detections(), 0);
        assert!(!p.found());
        assert!(capped_ms < 1000, "{} ms of ten seconds capped", capped_ms);
    }

    #[test]
    fn losses_at_rising_rates_are_no_policer() {
        // A fifth lost at random while the rate climbs (a slow start on a
        // lossy link): the intervals' rates never agree.
        let mut p = Policer::default();
        let (mut t, mut round) = (Instant::now(), 0);
        let mut rate = 100_000.0;
        for _ in 0..2000 {
            t += Duration::from_millis(1);
            round += 1;
            rate *= 1.003;
            let sent = rate / 1000.0;
            p.on_ack(t, round, (sent * 0.75) as u64, (sent * 0.25) as u64);
        }
        assert_eq!(p.detections(), 0);
        // And a little loss at a steady rate is none either.
        let mut p = Policer::default();
        for _ in 0..2000 {
            t += Duration::from_millis(1);
            round += 1;
            p.on_ack(t, round, 950, 50);
        }
        assert_eq!(p.detections(), 0);
    }

    #[test]
    fn rounds_track_their_minimum() {
        let mut t = Instant::now();
        let mut e = est();
        assert_eq!(e.round_min(), None);
        feed_round(&mut e, &mut t, &[30, 20, 25]);
        assert_eq!(e.round_min(), Some(Duration::from_millis(20)));
        assert_eq!(e.round_samples(), 3);
        assert_eq!(e.last_round_min(), None);
        let r = e.round();
        feed_round(&mut e, &mut t, &[40, 35]);
        assert_eq!(e.round(), r + 1);
        assert_eq!(e.last_round_min(), Some(Duration::from_millis(20)));
        assert_eq!(e.round_min(), Some(Duration::from_millis(35)));
        feed_round(&mut e, &mut t, &[50]);
        // The last complete round's minimum (35 ms) is 15 ms above the path
        // minimum (20 ms): a standing queue.
        assert_eq!(e.standing_queue(), Duration::from_millis(15));
    }

    #[test]
    fn pacing_rate_scales_with_window_and_respects_cap() {
        let mut c = Cubic::new(1000, 100, 1 << 30);
        let r = c.pacing_rate(Duration::from_millis(100), None);
        assert!((r - 2.0 * 100_000.0 / 0.1).abs() < 1.0); // slow-start gain 2
        assert_eq!(
            c.pacing_rate(Duration::from_millis(100), Some(50_000)),
            50_000.0
        );
        c.set_mss(500);
        assert_eq!(c.mss(), 500);
    }

    #[test]
    fn pacer_limits_rate() {
        let t0 = Instant::now();
        let mut p = Pacer::new(t0, 1_000_000.0, 10_000.0); // 1 MB/s, 10 KB burst
        assert!(p.try_take(10_000));
        assert!(!p.try_take(1));
        assert_eq!(p.delay_for(1000), Duration::from_millis(1));
        p.refill(t0 + Duration::from_millis(5));
        assert!(p.try_take(5000));
        assert!(!p.try_take(1));
        p.refill(t0 + Duration::from_secs(10));
        assert!(p.try_take(10_000)); // capped at burst
        assert!(!p.try_take(1));
        p.refund(4000); // datagram not sent after all
        assert!(p.try_take(4000));
        p.refund(1 << 20);
        assert!(p.try_take(10_000)); // refunds never exceed the burst
        assert!(!p.try_take(1));
    }

    #[test]
    fn burst_scales_with_rate_within_bounds() {
        assert_eq!(burst_for_rate(1_000.0, 1000), 16_000.0); // floor: 16 chunks
        assert_eq!(burst_for_rate(125_000_000.0, 1000), 125_000.0); // 1 ms at 1 Gbit/s
        assert_eq!(burst_for_rate(1e12, 1000), 1_024_000.0); // ceiling: 1024 chunks
    }
}
