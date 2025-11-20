// src/connectivity/stun/retransmission.rs
//! STUN Retransmission Logic
//!
//! RFC 8489 Section 14.3: Retransmissions
//!
//! Initial RTO = 500ms (or RTT estimate if available)
//! RTO doubles with each retransmission
//! Maximum Rc = 7 retransmissions
//! Final timeout = 39.5 * RTO (for Rm=16)

use std::time::{Duration, Instant};

use super::constants::{INITIAL_RTO_MS, MAX_RETRANSMISSIONS, RM};

/// Configuration for retransmission behavior
#[derive(Debug, Clone)]
pub struct RetransmissionConfig {
    /// Initial RTO in milliseconds
    pub initial_rto_ms: u64,

    /// Maximum number of retransmissions
    pub max_retransmissions: u32,

    /// Rm factor for final timeout calculation
    pub rm: u32,
}

impl Default for RetransmissionConfig {
    fn default() -> Self {
        Self {
            initial_rto_ms: INITIAL_RTO_MS,
            max_retransmissions: MAX_RETRANSMISSIONS,
            rm: RM,
        }
    }
}

impl RetransmissionConfig {
    /// Create with custom initial RTO
    pub fn with_rto(initial_rto_ms: u64) -> Self {
        Self {
            initial_rto_ms,
            ..Default::default()
        }
    }

    /// Calculate total timeout duration
    ///
    /// Total = RTO * (2^Rc - 1) + RTO * Rm
    /// For default values: 500 * (2^7 - 1) + 500 * 16 = 63500 + 8000 = 71500ms
    pub fn total_timeout(&self) -> Duration {
        let rto = Duration::from_millis(self.initial_rto_ms);
        let rc = self.max_retransmissions;
        let rm = self.rm;

        // Sum of RTOs: RTO + 2*RTO + 4*RTO + ... + 2^(Rc-1)*RTO = RTO * (2^Rc - 1)
        let sum_rtos = rto * ((1 << rc) - 1);

        // Final wait is RTO * Rm
        let final_wait = rto * rm;

        sum_rtos + final_wait
    }
}

/// State of a retransmission timer
#[derive(Debug)]
pub struct RetransmissionState {
    /// Configuration
    config: RetransmissionConfig,

    /// Current RTO
    current_rto: Duration,

    /// Number of retransmissions sent
    retransmission_count: u32,

    /// When the transaction started
    started_at: Instant,

    /// When the last transmission was sent
    last_transmission: Instant,

    /// Whether we're in the final wait period
    in_final_wait: bool,
}

impl RetransmissionState {
    /// Create a new retransmission state
    pub fn new(config: RetransmissionConfig) -> Self {
        let now = Instant::now();
        let initial_rto = Duration::from_millis(config.initial_rto_ms);

        Self {
            config,
            current_rto: initial_rto,
            retransmission_count: 0,
            started_at: now,
            last_transmission: now,
            in_final_wait: false,
        }
    }

    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(RetransmissionConfig::default())
    }

    /// Check if we should retransmit now
    pub fn should_retransmit(&self) -> bool {
        if self.in_final_wait {
            return false;
        }

        let elapsed = self.last_transmission.elapsed();
        elapsed >= self.current_rto
    }

    /// Check if the transaction has timed out
    pub fn is_timed_out(&self) -> bool {
        let total_elapsed = self.started_at.elapsed();
        total_elapsed >= self.config.total_timeout()
    }

    /// Record a retransmission
    ///
    /// Returns true if we can retransmit, false if we've exceeded max
    pub fn record_retransmission(&mut self) -> bool {
        if self.retransmission_count >= self.config.max_retransmissions {
            // Enter final wait period
            self.in_final_wait = true;
            return false;
        }

        self.retransmission_count += 1;
        self.last_transmission = Instant::now();

        // Double the RTO for next time
        self.current_rto *= 2;

        true
    }

    /// Get the time until next retransmission or timeout
    pub fn time_until_next_action(&self) -> Duration {
        if self.in_final_wait {
            // Calculate remaining final wait time
            let final_wait = Duration::from_millis(self.config.initial_rto_ms) * self.config.rm;
            let elapsed_in_final = self.last_transmission.elapsed();
            if elapsed_in_final >= final_wait {
                Duration::ZERO
            } else {
                final_wait - elapsed_in_final
            }
        } else {
            // Time until next retransmission
            let elapsed = self.last_transmission.elapsed();
            if elapsed >= self.current_rto {
                Duration::ZERO
            } else {
                self.current_rto - elapsed
            }
        }
    }

    /// Get current retransmission count
    pub fn retransmission_count(&self) -> u32 {
        self.retransmission_count
    }

    /// Get current RTO
    pub fn current_rto(&self) -> Duration {
        self.current_rto
    }

    /// Get elapsed time since start
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Update RTO based on measured RTT
    ///
    /// This can be used to improve RTO for subsequent requests
    pub fn update_rto_from_rtt(&mut self, rtt: Duration) {
        // Simple approach: use RTT as new base RTO
        // More sophisticated would use EWMA like TCP
        self.current_rto = rtt;
    }
}

/// Timer for managing retransmissions
pub struct RetransmissionTimer {
    state: RetransmissionState,
}

impl RetransmissionTimer {
    /// Create a new timer with default config
    pub fn new() -> Self {
        Self {
            state: RetransmissionState::default_config(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: RetransmissionConfig) -> Self {
        Self {
            state: RetransmissionState::new(config),
        }
    }

    /// Start the timer (resets state)
    pub fn start(&mut self) {
        self.state = RetransmissionState::new(self.state.config.clone());
    }

    /// Get next action to take
    pub fn next_action(&mut self) -> RetransmissionAction {
        if self.state.is_timed_out() {
            return RetransmissionAction::Timeout;
        }

        if self.state.should_retransmit() {
            if self.state.record_retransmission() {
                RetransmissionAction::Retransmit {
                    attempt: self.state.retransmission_count,
                    rto: self.state.current_rto,
                }
            } else {
                RetransmissionAction::WaitFinal {
                    duration: self.state.time_until_next_action(),
                }
            }
        } else {
            RetransmissionAction::Wait {
                duration: self.state.time_until_next_action(),
            }
        }
    }

    /// Get state reference
    pub fn state(&self) -> &RetransmissionState {
        &self.state
    }
}

impl Default for RetransmissionTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to take based on timer state
#[derive(Debug)]
pub enum RetransmissionAction {
    /// Wait for the specified duration before checking again
    Wait { duration: Duration },

    /// Retransmit the message
    Retransmit { attempt: u32, rto: Duration },

    /// Wait for final timeout
    WaitFinal { duration: Duration },

    /// Transaction has timed out
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_default_config() {
        let config = RetransmissionConfig::default();
        assert_eq!(config.initial_rto_ms, 500);
        assert_eq!(config.max_retransmissions, 7);
        assert_eq!(config.rm, 16);
    }

    #[test]
    fn test_total_timeout() {
        let config = RetransmissionConfig::default();
        let total = config.total_timeout();

        // Should be approximately 71.5 seconds for default values
        // RTO * (2^7 - 1) + RTO * 16 = 500 * 127 + 500 * 16 = 71500ms
        assert_eq!(total.as_millis(), 71500);
    }

    #[test]
    fn test_retransmission_state() {
        let config = RetransmissionConfig {
            initial_rto_ms: 10, // Short for testing
            max_retransmissions: 3,
            rm: 2,
        };

        let mut state = RetransmissionState::new(config);

        // Initial state
        assert_eq!(state.retransmission_count(), 0);
        assert_eq!(state.current_rto().as_millis(), 10);

        // Record retransmissions
        assert!(state.record_retransmission()); // 1st, RTO = 20ms
        assert_eq!(state.retransmission_count(), 1);
        assert_eq!(state.current_rto().as_millis(), 20);

        assert!(state.record_retransmission()); // 2nd, RTO = 40ms
        assert_eq!(state.retransmission_count(), 2);
        assert_eq!(state.current_rto().as_millis(), 40);

        assert!(state.record_retransmission()); // 3rd, RTO = 80ms
        assert_eq!(state.retransmission_count(), 3);
        assert_eq!(state.current_rto().as_millis(), 80);

        // Max reached
        assert!(!state.record_retransmission());
        assert!(state.in_final_wait);
    }

    #[test]
    fn test_timer_actions() {
        let config = RetransmissionConfig {
            initial_rto_ms: 1, // Very short for testing
            max_retransmissions: 2,
            rm: 1,
        };

        let mut timer = RetransmissionTimer::with_config(config);
        timer.start();

        // Initial action should be wait
        match timer.next_action() {
            RetransmissionAction::Wait { .. } => {}
            _ => panic!("Expected Wait"),
        }

        // After RTO, should retransmit
        sleep(Duration::from_millis(2));
        match timer.next_action() {
            RetransmissionAction::Retransmit { attempt, .. } => {
                assert_eq!(attempt, 1);
            }
            _ => panic!("Expected Retransmit"),
        }
    }

    #[test]
    fn test_rto_update() {
        let mut state = RetransmissionState::default_config();

        // Simulate measuring RTT
        let measured_rtt = Duration::from_millis(100);
        state.update_rto_from_rtt(measured_rtt);

        assert_eq!(state.current_rto(), measured_rtt);
    }
}
