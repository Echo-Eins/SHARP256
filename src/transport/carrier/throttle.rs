//! Whether UDP is held back: answered, but slowly — a network that polices
//! UDP to a trickle, or drops a share of it, while TCP passes untouched.
//!
//! **Why a trial.** From inside, a policer looks just like a slow link with
//! a shallow buffer: losses whenever the sender goes over a rate, and that
//! rate is all that gets through. Nothing the session measures over UDP
//! alone tells the two apart. What does is the other carrier: so when UDP
//! looks suspect, the session moves to a stream for a few seconds and
//! measures what gets through there, and keeps to the faster.
//!
//! **When UDP is suspect**, over a window of [`WINDOW`]: a tenth or more of
//! what was sent had to be sent again; or a hundredth, with at least
//! [`LONG_LEFT`] still to go at the rate measured — a trial costs a few
//! seconds, worth spending on a long transfer even on a hunch. Not before
//! the transfer has a window's worth behind it, and not when too little is
//! left for the trial to pay.
//!
//! **The trial.** The session moves to a stream (one already up, or one
//! dialled now). [`SETTLE`] is given to the receiver, which goes on
//! answering over UDP until its own patience with UDP runs out (see
//! `path::DIRECT_GRACE`), then [`MEASURE`] measures. TCP wins if it carries
//! at least [`BETTER`] times what UDP did.
//!
//! **Hysteresis.** A won trial keeps the session on the stream for
//! [`KEEP`], twice as long after each win in a row, up to [`HOLD_MAX`]:
//! only then is UDP asked again, and a UDP that is still held back is found
//! out again and left again for longer. A lost trial puts the next one off
//! for [`RETRY`], twice as long after each loss in a row, up to
//! [`HOLD_MAX`]: a path where TCP is no better is not asked over and over.
//! A stream that dies, or never comes, ends the trial as a loss.

use std::time::{Duration, Instant};

/// How long UDP is measured at a time.
pub const WINDOW: Duration = Duration::from_secs(5);
/// What a window must have sent to say anything.
const ENOUGH: u64 = 64 << 10;
/// Resent over sent, past which UDP is suspect whatever is left.
const HEAVY_LOSS: f64 = 0.10;
/// Resent over sent, past which UDP is suspect when much is left.
const SOME_LOSS: f64 = 0.01;
/// What "much is left" is.
pub const LONG_LEFT: Duration = Duration::from_secs(30);
/// Too little left for a trial to pay, whatever the loss.
const SHORT_LEFT: Duration = Duration::from_secs(15);
/// How long the receiver is given to follow onto the stream, and how long
/// TCP is then measured.
pub const SETTLE: Duration = Duration::from_secs(4);
pub const MEASURE: Duration = Duration::from_secs(6);
/// How long a trial may wait for the session to get onto a stream.
const STREAM_WAIT: Duration = Duration::from_secs(15);
/// How much faster TCP has to be.
pub const BETTER: f64 = 1.25;
/// The first hold after a win, and the first wait after a loss.
pub const KEEP: Duration = Duration::from_secs(120);
pub const RETRY: Duration = Duration::from_secs(60);
pub const HOLD_MAX: Duration = Duration::from_secs(1800);

/// The session's counters at one moment.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub now: Instant,
    /// Bytes sent, resends included, and those of them that were resends.
    pub sent: u64,
    pub resent: u64,
    /// Bytes the receiver says it holds, and those it does not yet.
    pub delivered: u64,
    pub left: u64,
    /// Whether the session runs on a stream.
    pub on_stream: bool,
}

/// What has to be done, or said.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Nothing,
    /// UDP is suspect: get the session onto a stream, for a trial.
    Try {
        loss: f64,
        rate: f64,
    },
    /// TCP won (rates in bytes per second): keep to it for `hold`.
    Keep {
        udp: f64,
        tcp: f64,
        hold: Duration,
    },
    /// TCP lost: back to UDP; no trial for `hold`.
    Back {
        udp: f64,
        tcp: f64,
        hold: Duration,
    },
    /// The session never got onto a stream, or the stream died under the
    /// trial: no trial for `hold`.
    GaveUp {
        hold: Duration,
    },
}

#[derive(Debug, Clone, Copy)]
struct Mark {
    at: Instant,
    sent: u64,
    resent: u64,
    delivered: u64,
}

impl Mark {
    fn of(s: &Sample) -> Self {
        Self {
            at: s.now,
            sent: s.sent,
            resent: s.resent,
            delivered: s.delivered,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Trial {
    asked_at: Instant,
    /// What UDP carried, in bytes per second.
    udp: f64,
    /// When the session got onto the stream.
    moved_at: Option<Instant>,
    /// Where the measurement starts, once settled.
    from: Option<Mark>,
}

#[derive(Debug)]
pub struct Throttle {
    window: Option<Mark>,
    trial: Option<Trial>,
    /// Until when a won trial keeps the session on the stream.
    keep_until: Option<Instant>,
    /// No trial before this.
    next_trial: Instant,
    wins: u32,
    losses: u32,
}

/// `base` doubled for each of `n` in a row past the first, up to [`HOLD_MAX`].
fn doubled(base: Duration, n: u32) -> Duration {
    base.saturating_mul(1u32 << n.saturating_sub(1).min(10))
        .min(HOLD_MAX)
}

impl Throttle {
    pub fn new(now: Instant) -> Self {
        Self {
            window: None,
            trial: None,
            keep_until: None,
            next_trial: now,
            wins: 0,
            losses: 0,
        }
    }

    /// Whether the session is to get onto a stream though UDP answers: a
    /// trial waiting for it.
    pub fn wants_stream(&self) -> bool {
        self.trial.is_some_and(|t| t.moved_at.is_none())
    }

    /// Whether the session, on a stream, stays there though UDP answers: a
    /// trial under way — from the moment it is asked for, since the session
    /// may be on the stream before the next tick says so — or the hold of a
    /// won one.
    pub fn holds_stream(&self, now: Instant) -> bool {
        self.trial.is_some() || self.keep_until.is_some_and(|k| now < k)
    }

    /// Takes the session's counters, now and then — a few times a second is
    /// plenty — and says what to do.
    pub fn tick(&mut self, s: Sample) -> Verdict {
        let Some(mut t) = self.trial else {
            return self.watch(s);
        };
        match (s.on_stream, t.moved_at) {
            // Waiting for the session to get onto a stream.
            (false, None) => {
                if s.now.saturating_duration_since(t.asked_at) >= STREAM_WAIT {
                    return self.lost(s.now);
                }
                Verdict::Nothing
            }
            // Off the stream under the trial: it died, or the session was
            // taken elsewhere.
            (false, Some(_)) => self.lost(s.now),
            (true, None) => {
                t.moved_at = Some(s.now);
                self.trial = Some(t);
                Verdict::Nothing
            }
            (true, Some(moved)) => {
                let Some(from) = t.from else {
                    if s.now.saturating_duration_since(moved) >= SETTLE {
                        t.from = Some(Mark::of(&s));
                        self.trial = Some(t);
                    }
                    return Verdict::Nothing;
                };
                let took = s.now.saturating_duration_since(from.at);
                if took < MEASURE {
                    return Verdict::Nothing;
                }
                let tcp = s.delivered.saturating_sub(from.delivered) as f64 / took.as_secs_f64();
                self.trial = None;
                self.window = None;
                if tcp >= BETTER * t.udp {
                    self.wins += 1;
                    self.losses = 0;
                    let hold = doubled(KEEP, self.wins);
                    self.keep_until = Some(s.now + hold);
                    Verdict::Keep {
                        udp: t.udp,
                        tcp,
                        hold,
                    }
                } else {
                    self.wins = 0;
                    self.losses += 1;
                    let hold = doubled(RETRY, self.losses);
                    self.next_trial = s.now + hold;
                    Verdict::Back {
                        udp: t.udp,
                        tcp,
                        hold,
                    }
                }
            }
        }
    }

    fn lost(&mut self, now: Instant) -> Verdict {
        self.trial = None;
        self.window = None;
        self.wins = 0;
        self.losses += 1;
        let hold = doubled(RETRY, self.losses);
        self.next_trial = now + hold;
        Verdict::GaveUp { hold }
    }

    /// No trial: UDP is measured while the session runs on it.
    fn watch(&mut self, s: Sample) -> Verdict {
        if s.on_stream {
            // On a stream for its own reasons (UDP went quiet), or held
            // there: nothing to measure UDP by.
            self.window = None;
            if self.keep_until.is_some_and(|k| s.now >= k) {
                self.keep_until = None;
            }
            return Verdict::Nothing;
        }
        // Back on UDP: whatever kept the session off it is over.
        self.keep_until = None;
        let Some(w) = self.window else {
            self.window = Some(Mark::of(&s));
            return Verdict::Nothing;
        };
        let took = s.now.saturating_duration_since(w.at);
        if took < WINDOW {
            return Verdict::Nothing;
        }
        self.window = Some(Mark::of(&s));
        let sent = s.sent.saturating_sub(w.sent);
        if sent < ENOUGH || s.now < self.next_trial {
            return Verdict::Nothing;
        }
        let loss = s.resent.saturating_sub(w.resent) as f64 / sent as f64;
        let rate = s.delivered.saturating_sub(w.delivered) as f64 / took.as_secs_f64();
        let left = if rate > 0.0 {
            Duration::from_secs_f64((s.left as f64 / rate).min(1e9))
        } else {
            Duration::MAX
        };
        let suspect =
            left >= SHORT_LEFT && (loss >= HEAVY_LOSS || (loss >= SOME_LOSS && left >= LONG_LEFT));
        if !suspect {
            return Verdict::Nothing;
        }
        self.trial = Some(Trial {
            asked_at: s.now,
            udp: rate,
            moved_at: None,
            from: None,
        });
        Verdict::Try { loss, rate }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session as `tick` sees it: counters that move at given rates.
    struct Run {
        t: Throttle,
        s: Sample,
    }

    impl Run {
        fn new(size: u64) -> Self {
            let now = Instant::now();
            Self {
                t: Throttle::new(now),
                s: Sample {
                    now,
                    sent: 0,
                    resent: 0,
                    delivered: 0,
                    left: size,
                    on_stream: false,
                },
            }
        }

        /// `secs` of carrying `rate` bytes a second, of which `loss` had to
        /// be sent again, ticking every quarter second; the verdicts that
        /// were not `Nothing`.
        fn carry(&mut self, secs: f64, rate: f64, loss: f64) -> Vec<Verdict> {
            let mut said = Vec::new();
            let steps = (secs * 4.0) as u32;
            for _ in 0..steps {
                let got = (rate / 4.0) as u64;
                let sent = (got as f64 / (1.0 - loss)) as u64;
                self.s.now += Duration::from_millis(250);
                self.s.sent += sent;
                self.s.resent += sent - got;
                self.s.delivered += got;
                self.s.left = self.s.left.saturating_sub(got);
                let v = self.t.tick(self.s);
                if v != Verdict::Nothing {
                    said.push(v);
                }
            }
            said
        }
    }

    const MB: f64 = 1e6;

    #[test]
    fn a_clean_path_is_left_alone() {
        let mut r = Run::new(10_000_000_000);
        assert!(r.carry(60.0, 10.0 * MB, 0.001).is_empty());
        assert!(!r.t.wants_stream());
    }

    #[test]
    fn heavy_loss_starts_a_trial_and_a_faster_stream_is_kept() {
        let mut r = Run::new(10_000_000_000);
        let said = r.carry(6.0, 1.0 * MB, 0.3);
        assert!(
            matches!(said[..], [Verdict::Try { loss, .. }] if loss > 0.25),
            "{:?}",
            said
        );
        assert!(r.t.wants_stream());
        // On the stream, five times as fast.
        r.s.on_stream = true;
        let said = r.carry(
            SETTLE.as_secs_f64() + MEASURE.as_secs_f64() + 1.0,
            5.0 * MB,
            0.0,
        );
        let [Verdict::Keep { udp, tcp, hold }] = said[..] else {
            panic!("{:?}", said)
        };
        assert!(tcp > 4.0 * udp);
        assert_eq!(hold, KEEP);
        assert!(r.t.holds_stream(r.s.now));
        // Held until the hold runs out, and then UDP may be asked again.
        r.carry(KEEP.as_secs_f64() - 2.0, 5.0 * MB, 0.0);
        assert!(r.t.holds_stream(r.s.now));
        r.carry(3.0, 5.0 * MB, 0.0);
        assert!(!r.t.holds_stream(r.s.now));
    }

    #[test]
    fn a_stream_no_faster_sends_the_session_back_and_puts_trials_off() {
        let mut r = Run::new(10_000_000_000);
        assert!(matches!(
            r.carry(6.0, 1.0 * MB, 0.3)[..],
            [Verdict::Try { .. }]
        ));
        r.s.on_stream = true;
        let said = r.carry(11.0, 1.1 * MB, 0.0);
        assert!(
            matches!(said[..], [Verdict::Back { hold, .. }] if hold == RETRY),
            "{:?}",
            said
        );
        assert!(!r.t.holds_stream(r.s.now), "free to go back to UDP");
        // Back on UDP, as lossy as before: no trial until the wait is over.
        r.s.on_stream = false;
        assert!(r.carry(RETRY.as_secs_f64() - 1.0, 1.0 * MB, 0.3).is_empty());
        let said = r.carry(6.0, 1.0 * MB, 0.3);
        assert!(matches!(said[..], [Verdict::Try { .. }]), "{:?}", said);
        // A second loss in a row waits twice as long.
        r.s.on_stream = true;
        let said = r.carry(11.0, 1.0 * MB, 0.0);
        assert!(
            matches!(said[..], [Verdict::Back { hold, .. }] if hold == 2 * RETRY),
            "{:?}",
            said
        );
    }

    #[test]
    fn some_loss_is_suspect_only_with_much_left() {
        // Two per cent lost, 25 MB left at 1 MB/s: not worth a trial.
        let mut r = Run::new(30_000_000);
        assert!(r.carry(6.0, 1.0 * MB, 0.02).is_empty());
        // The same with an hour to go is.
        let mut r = Run::new(3_600_000_000);
        assert!(matches!(
            r.carry(6.0, 1.0 * MB, 0.02)[..],
            [Verdict::Try { .. }]
        ));
    }

    #[test]
    fn nothing_is_tried_near_the_end() {
        let mut r = Run::new(14_000_000);
        assert!(r.carry(13.0, 1.0 * MB, 0.5).is_empty());
    }

    #[test]
    fn a_trial_that_never_gets_a_stream_gives_up() {
        let mut r = Run::new(10_000_000_000);
        assert!(matches!(
            r.carry(6.0, 1.0 * MB, 0.3)[..],
            [Verdict::Try { .. }]
        ));
        let said = r.carry(STREAM_WAIT.as_secs_f64() + 1.0, 1.0 * MB, 0.3);
        assert!(
            matches!(said[..], [Verdict::GaveUp { hold }] if hold == RETRY),
            "{:?}",
            said
        );
        assert!(!r.t.wants_stream());
    }

    #[test]
    fn a_stream_that_dies_under_the_trial_ends_it() {
        let mut r = Run::new(10_000_000_000);
        r.carry(6.0, 1.0 * MB, 0.3);
        r.s.on_stream = true;
        r.carry(2.0, 5.0 * MB, 0.0);
        assert!(r.t.holds_stream(r.s.now));
        r.s.on_stream = false;
        let said = r.carry(1.0, 1.0 * MB, 0.3);
        assert!(matches!(said[..], [Verdict::GaveUp { .. }]), "{:?}", said);
        assert!(!r.t.holds_stream(r.s.now));
    }

    #[test]
    fn wins_in_a_row_hold_longer_up_to_a_limit() {
        assert_eq!(doubled(KEEP, 1), KEEP);
        assert_eq!(doubled(KEEP, 2), 2 * KEEP);
        assert_eq!(doubled(KEEP, 4), 8 * KEEP);
        assert_eq!(doubled(KEEP, 5), HOLD_MAX);
        assert_eq!(doubled(KEEP, 1000), HOLD_MAX);
    }
}
