//! Sliding-window replay protection for packet numbers (RFC 6479 style).
//!
//! Only packets that passed authentication may be offered to the window,
//! otherwise forged packet numbers could move it.

const WORDS: usize = 128;
/// Packets the window remembers behind the highest packet number seen.
pub const WINDOW: u64 = (WORDS * 64) as u64;

#[derive(Clone)]
pub struct ReplayWindow {
    top: Option<u64>,
    bits: Box<[u64; WORDS]>,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            top: None,
            bits: Box::new([0; WORDS]),
        }
    }

    fn slot(pn: u64) -> (usize, u64) {
        let i = (pn % WINDOW) as usize;
        (i / 64, 1u64 << (i % 64))
    }

    /// Records `pn`; false if it was seen before or is older than the window.
    pub fn accept(&mut self, pn: u64) -> bool {
        match self.top {
            Some(top) if pn <= top => {
                if top - pn >= WINDOW {
                    return false;
                }
                let (w, b) = Self::slot(pn);
                if self.bits[w] & b != 0 {
                    return false;
                }
                self.bits[w] |= b;
                true
            }
            Some(top) => {
                // Forget the slots the window slides over.
                if pn - top >= WINDOW {
                    self.bits.fill(0);
                } else {
                    for q in top + 1..pn {
                        let (w, b) = Self::slot(q);
                        self.bits[w] &= !b;
                    }
                }
                let (w, b) = Self::slot(pn);
                self.bits[w] = (self.bits[w] & !b) | b;
                self.top = Some(pn);
                true
            }
            None => {
                let (w, b) = Self::slot(pn);
                self.bits[w] |= b;
                self.top = Some(pn);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicates_and_stale() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(!w.accept(5));
        assert!(w.accept(3));
        assert!(!w.accept(3));
        assert!(w.accept(100));
        assert!(w.accept(6));
        assert!(!w.accept(100));
        // Jump far ahead: old numbers fall out of the window.
        assert!(w.accept(100 + WINDOW + 10));
        assert!(!w.accept(50));
        assert!(!w.accept(100 + 5)); // older than the window now
        assert!(w.accept(100 + WINDOW + 9)); // inside the window, unseen
        assert!(!w.accept(100 + WINDOW + 9));
    }

    #[test]
    fn matches_a_set_model() {
        let mut w = ReplayWindow::new();
        let mut seen = std::collections::HashSet::new();
        let mut top = 0u64;
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // Mostly increasing numbers with reordering and duplicates.
            let pn = (top + 64).saturating_sub(x % 200) + (x >> 60);
            let expect = !(seen.contains(&pn) || (top >= WINDOW && pn <= top - WINDOW));
            assert_eq!(w.accept(pn), expect, "pn {} top {}", pn, top);
            if expect {
                seen.insert(pn);
                top = top.max(pn);
            }
        }
    }
}
