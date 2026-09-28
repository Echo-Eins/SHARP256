//! Keeping a NAT mapping alive while nothing else flows through it.
//!
//! A NAT forgets a UDP mapping that has been idle for long enough, and
//! from then on the address it stood for leads nowhere: the receiver's
//! published address stops working, and so does its registration with a
//! relay, until it sends something again. RFC 4787 (REQ-5) asks NATs to
//! keep an idle mapping for at least two minutes, but plenty of home
//! routers and carrier-grade NATs keep one for thirty seconds or less.
//!
//! So something is sent more often than that. How often is the one
//! question, and it is answered in three layers:
//!
//! 1. By default, every 15 seconds — the default RFC 8445 (section 11)
//!    gives for ICE keepalives, which exist for exactly this reason.
//! 2. When the mapping is measured (RFC 5780 section 4.6, see
//!    `behaviour::binding_lifetime`), every half of what it lasted, between
//!    [`FLOOR`] and [`CEILING`]: a NAT that keeps mappings for ten minutes
//!    needs no packet every 15 seconds, and a battery-powered host is glad
//!    of the difference.
//! 3. When a mapping is seen to have changed anyway — the relay or STUN
//!    server sees us at a new address — whatever the interval was, it was
//!    too long: it is halved, down to the floor.
//!
//! Each wait is jittered by a tenth either way, so that hosts behind one
//! NAT that started together do not keep refreshing in lockstep.

use std::time::Duration;

/// The interval before anything is known (RFC 8445 section 11).
pub const DEFAULT: Duration = Duration::from_secs(15);
/// Never more often than this: a NAT that forgets a mapping within ten
/// seconds cannot be kept open by any sensible amount of traffic.
pub const FLOOR: Duration = Duration::from_secs(5);
/// Never less often than this, whatever a measurement said: a measurement
/// is of one mapping at one moment, and some margin is cheap.
pub const CEILING: Duration = Duration::from_secs(60);

/// How often to refresh one mapping, and what has been learned about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keepalive {
    interval: Duration,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self { interval: DEFAULT }
    }
}

impl Keepalive {
    /// Starts from a measured lifetime when one is known.
    pub fn new(lifetime: Option<Duration>) -> Self {
        let mut k = Self::default();
        if let Some(l) = lifetime {
            k.lifetime_measured(l);
        }
        k
    }

    /// The interval, without jitter.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// How long to wait before the next refresh: the interval, give or
    /// take a tenth.
    pub fn next(&self) -> Duration {
        use rand::Rng;
        let tenth = self.interval.as_millis() as u64 / 10;
        let jitter = rand::thread_rng().gen_range(0..=2 * tenth);
        self.interval - Duration::from_millis(tenth) + Duration::from_millis(jitter)
    }

    /// A mapping measured to last `lifetime`: refresh at half of it.
    pub fn lifetime_measured(&mut self, lifetime: Duration) {
        self.interval = (lifetime / 2).clamp(FLOOR, CEILING);
    }

    /// The mapping changed although it was being refreshed: the refreshes
    /// were too far apart. Returns whether the interval got shorter.
    pub fn mapping_changed(&mut self) -> bool {
        let shorter = (self.interval / 2).max(FLOOR);
        let changed = shorter < self.interval;
        self.interval = shorter;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_where_rfc8445_says() {
        let k = Keepalive::default();
        assert_eq!(k.interval(), DEFAULT);
        for _ in 0..100 {
            let n = k.next();
            assert!(n >= DEFAULT * 9 / 10 && n <= DEFAULT * 11 / 10, "{:?}", n);
        }
    }

    #[test]
    fn a_measurement_sets_half_its_lifetime_within_bounds() {
        let mut k = Keepalive::new(Some(Duration::from_secs(60)));
        assert_eq!(k.interval(), Duration::from_secs(30));
        k.lifetime_measured(Duration::from_secs(600));
        assert_eq!(k.interval(), CEILING);
        k.lifetime_measured(Duration::from_secs(4));
        assert_eq!(k.interval(), FLOOR);
    }

    #[test]
    fn a_changed_mapping_halves_the_interval_down_to_the_floor() {
        let mut k = Keepalive::default();
        assert!(k.mapping_changed());
        assert_eq!(k.interval(), DEFAULT / 2);
        assert!(!{
            k.mapping_changed();
            k.mapping_changed()
        });
        assert_eq!(k.interval(), FLOOR);
    }
}
