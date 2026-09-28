//! A set of disjoint half-open byte ranges `[start, end)` backed by a BTreeMap.
//!
//! Used by the receiver to track which bytes of the file have arrived, by the
//! sender to track what still has to be (re)sent, and by the resume logic to
//! persist progress. All operations keep the set normalized: ranges never
//! overlap and adjacent ranges are merged.

use std::collections::BTreeMap;

pub type Range = (u64, u64);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeSet {
    map: BTreeMap<u64, u64>,
    /// Sum of the lengths of the ranges, kept up to date by every change so
    /// that asking for it costs nothing: it is read on every ACK, and a set
    /// broken into many pieces would otherwise make each one a walk.
    bytes: u64,
}

#[inline]
fn overlap(a: u64, b: u64, c: u64, d: u64) -> u64 {
    let lo = a.max(c);
    let hi = b.min(d);
    hi.saturating_sub(lo)
}

impl RangeSet {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            bytes: 0,
        }
    }

    /// Builds a set from arbitrary (possibly overlapping) ranges.
    pub fn from_ranges<I: IntoIterator<Item = Range>>(ranges: I) -> Self {
        let mut set = Self::new();
        for (s, e) in ranges {
            set.insert(s, e);
        }
        set
    }

    /// Inserts `[start, end)`. Returns the number of bytes that were not
    /// already present.
    pub fn insert(&mut self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        let (orig_start, orig_end) = (start, end);
        let mut added = end - start;
        let mut start = start;
        let mut end = end;

        if let Some((&ps, &pe)) = self.map.range(..=start).next_back() {
            if pe >= start {
                added -= overlap(ps, pe, orig_start, orig_end);
                start = ps;
                end = end.max(pe);
                self.map.remove(&ps);
            }
        }
        let followers: Vec<u64> = self.map.range(start..=end).map(|(&k, _)| k).collect();
        for k in followers {
            let e = self.map.remove(&k).expect("key present");
            added -= overlap(k, e, orig_start, orig_end);
            end = end.max(e);
        }
        self.map.insert(start, end);
        self.bytes += added;
        added
    }

    /// Whether inserting `[start, end)` would make one more range: nothing
    /// already present overlaps it or touches either end. Only such an
    /// insert grows the set; any other extends or joins what is there.
    pub fn would_add_range(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return false;
        }
        if let Some((_, &pe)) = self.map.range(..=start).next_back() {
            if pe >= start {
                return false;
            }
        }
        self.map.range(start..=end).next().is_none()
    }

    /// Removes `[start, end)`. Returns the number of bytes actually removed.
    pub fn remove(&mut self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        let mut removed = 0;
        let mut to_insert: Vec<Range> = Vec::new();
        let mut to_remove: Vec<u64> = Vec::new();

        let first_key = self
            .map
            .range(..=start)
            .next_back()
            .map(|(&k, _)| k)
            .unwrap_or(start);
        for (&s, &e) in self.map.range(first_key..) {
            if s >= end {
                break;
            }
            if e <= start {
                continue;
            }
            removed += overlap(s, e, start, end);
            to_remove.push(s);
            if s < start {
                to_insert.push((s, start));
            }
            if e > end {
                to_insert.push((end, e));
            }
        }
        for k in to_remove {
            self.map.remove(&k);
        }
        for (s, e) in to_insert {
            self.map.insert(s, e);
        }
        self.bytes -= removed;
        removed
    }

    /// True when every byte of `[start, end)` is present.
    pub fn contains(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return true;
        }
        match self.map.range(..=start).next_back() {
            Some((_, &e)) => e >= end,
            None => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Number of ranges.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Total number of bytes present.
    pub fn total(&self) -> u64 {
        self.bytes
    }

    /// End of the contiguous run that covers `from`; `from` itself if it is
    /// not covered. `contiguous_from(0)` is the classic cumulative ACK point.
    pub fn contiguous_from(&self, from: u64) -> u64 {
        match self.map.range(..=from).next_back() {
            Some((_, &e)) if e > from => e,
            _ => from,
        }
    }

    /// Gaps inside `[from, to)`, lowest first, at most `limit` entries.
    pub fn holes(&self, from: u64, to: u64, limit: usize) -> Vec<Range> {
        let mut out = Vec::new();
        if from >= to || limit == 0 {
            return out;
        }
        let mut cursor = from;
        let first_key = self
            .map
            .range(..=from)
            .next_back()
            .map(|(&k, _)| k)
            .unwrap_or(from);
        for (&s, &e) in self.map.range(first_key..) {
            if s >= to {
                break;
            }
            if e <= cursor {
                continue;
            }
            if s > cursor {
                out.push((cursor, s.min(to)));
                if out.len() >= limit {
                    return out;
                }
            }
            cursor = cursor.max(e);
            if cursor >= to {
                return out;
            }
        }
        if cursor < to {
            out.push((cursor, to));
        }
        out
    }

    pub fn iter(&self) -> impl Iterator<Item = Range> + '_ {
        self.map.iter().map(|(&s, &e)| (s, e))
    }

    pub fn first(&self) -> Option<Range> {
        self.map.iter().next().map(|(&s, &e)| (s, e))
    }

    /// End of the last range, if any.
    pub fn last_end(&self) -> Option<u64> {
        self.map.iter().next_back().map(|(_, &e)| e)
    }

    /// Removes and returns up to `max_len` bytes from the lowest range.
    pub fn take_first(&mut self, max_len: u64) -> Option<Range> {
        let (s, e) = self.first()?;
        let take_end = e.min(s.saturating_add(max_len.max(1)));
        self.map.remove(&s);
        if take_end < e {
            self.map.insert(take_end, e);
        }
        self.bytes -= take_end - s;
        Some((s, take_end))
    }

    /// Ranges of this set intersecting `[start, end)`, clipped to it.
    pub fn intersecting(&self, start: u64, end: u64) -> Vec<Range> {
        let mut out = Vec::new();
        if start >= end {
            return out;
        }
        let first_key = self
            .map
            .range(..=start)
            .next_back()
            .map(|(&k, _)| k)
            .unwrap_or(start);
        for (&s, &e) in self.map.range(first_key..) {
            if s >= end {
                break;
            }
            if e <= start {
                continue;
            }
            out.push((s.max(start), e.min(end)));
        }
        out
    }

    pub fn to_vec(&self) -> Vec<Range> {
        self.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_merges_and_counts_new_bytes() {
        let mut s = RangeSet::new();
        assert_eq!(s.insert(0, 10), 10);
        assert_eq!(s.insert(10, 20), 10); // adjacent -> merged
        assert_eq!(s.to_vec(), vec![(0, 20)]);
        assert_eq!(s.insert(5, 15), 0); // fully covered
        assert_eq!(s.insert(30, 40), 10);
        assert_eq!(s.insert(15, 35), 10); // bridges the gap 20..30
        assert_eq!(s.to_vec(), vec![(0, 40)]);
        assert_eq!(s.total(), 40);
        assert_eq!(s.insert(3, 3), 0);
    }

    #[test]
    fn insert_overlapping_several_ranges() {
        let mut s = RangeSet::from_ranges([(0, 10), (20, 30), (40, 50)]);
        assert_eq!(s.insert(5, 45), 20); // adds 10..20 and 30..40
        assert_eq!(s.to_vec(), vec![(0, 50)]);
    }

    #[test]
    fn remove_splits_and_clips() {
        let mut s = RangeSet::from_ranges([(0, 100)]);
        assert_eq!(s.remove(10, 20), 10);
        assert_eq!(s.to_vec(), vec![(0, 10), (20, 100)]);
        assert_eq!(s.remove(0, 5), 5);
        assert_eq!(s.remove(95, 200), 5);
        assert_eq!(s.to_vec(), vec![(5, 10), (20, 95)]);
        assert_eq!(s.remove(0, 200), 80);
        assert!(s.is_empty());
    }

    #[test]
    fn contiguous_and_holes() {
        let s = RangeSet::from_ranges([(0, 10), (20, 30), (35, 40)]);
        assert_eq!(s.contiguous_from(0), 10);
        assert_eq!(s.contiguous_from(10), 10);
        assert_eq!(s.contiguous_from(25), 30);
        assert_eq!(s.holes(0, 40, 10), vec![(10, 20), (30, 35)]);
        assert_eq!(s.holes(0, 50, 10), vec![(10, 20), (30, 35), (40, 50)]);
        assert_eq!(s.holes(0, 50, 2), vec![(10, 20), (30, 35)]);
        assert_eq!(s.holes(12, 27, 10), vec![(12, 20)]);
        assert!(s.holes(0, 10, 10).is_empty());
        assert!(RangeSet::new().holes(0, 0, 10).is_empty());
        assert_eq!(RangeSet::new().holes(0, 7, 10), vec![(0, 7)]);
    }

    #[test]
    fn contains_and_intersecting() {
        let s = RangeSet::from_ranges([(0, 10), (20, 30)]);
        assert!(s.contains(0, 10));
        assert!(s.contains(2, 8));
        assert!(!s.contains(5, 15));
        assert!(!s.contains(10, 20));
        assert!(s.contains(7, 7));
        assert_eq!(s.intersecting(5, 25), vec![(5, 10), (20, 25)]);
        assert!(s.intersecting(10, 20).is_empty());
    }

    #[test]
    fn take_first_pops_bounded_chunks() {
        let mut s = RangeSet::from_ranges([(0, 25), (100, 110)]);
        assert_eq!(s.take_first(10), Some((0, 10)));
        assert_eq!(s.take_first(10), Some((10, 20)));
        assert_eq!(s.take_first(10), Some((20, 25)));
        assert_eq!(s.take_first(10), Some((100, 110)));
        assert_eq!(s.take_first(10), None);
    }

    #[test]
    fn randomized_against_bitmap() {
        // Deterministic LCG so the test is reproducible without rand.
        let mut x: u64 = 0x9E3779B97F4A7C15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut set = RangeSet::new();
        let mut bits = vec![false; 512];
        for _ in 0..2000 {
            let a = next() % 512;
            let b = next() % 512;
            let (s, e) = if a <= b { (a, b) } else { (b, a) };
            if next() % 3 == 0 {
                let removed = set.remove(s, e);
                let mut expect = 0;
                for i in s..e {
                    if bits[i as usize] {
                        expect += 1;
                        bits[i as usize] = false;
                    }
                }
                assert_eq!(removed, expect);
            } else if next() % 5 == 0 {
                let before = set.total();
                if let Some((ts, te)) = set.take_first(1 + next() % 40) {
                    for i in ts..te {
                        assert!(bits[i as usize]);
                        bits[i as usize] = false;
                    }
                    assert_eq!(set.total(), before - (te - ts));
                }
            } else {
                // Only an insert that touches nothing makes one more range.
                let grows = set.would_add_range(s, e);
                let ranges = set.len();
                let added = set.insert(s, e);
                assert_eq!(set.len() == ranges + 1, grows, "[{}, {})", s, e);
                let mut expect = 0;
                for i in s..e {
                    if !bits[i as usize] {
                        expect += 1;
                        bits[i as usize] = true;
                    }
                }
                assert_eq!(added, expect);
            }
            // Normalization: sorted, disjoint, non-adjacent.
            let v = set.to_vec();
            for w in v.windows(2) {
                assert!(w[0].1 < w[1].0);
            }
            assert_eq!(set.total() as usize, bits.iter().filter(|b| **b).count());
            // Holes agree with bitmap gaps.
            let holes = set.holes(0, 512, usize::MAX);
            let mut expect = Vec::new();
            let mut i = 0;
            while i < 512 {
                if !bits[i] {
                    let st = i;
                    while i < 512 && !bits[i] {
                        i += 1;
                    }
                    expect.push((st as u64, i as u64));
                } else {
                    i += 1;
                }
            }
            assert_eq!(holes, expect);
        }
    }
}
