//! Timing leak detection in the manner of dudect (O. Reparaz, J. Balasch,
//! I. Verbauwhede, "Dude, is my code constant time?", DATE 2017): run an
//! operation on inputs of two classes in random order, time each run, and
//! ask with Welch's t-test whether the two distributions of times differ.
//! A |t| above 4.5 is taken as a leak (the paper's threshold); well below
//! it, no difference was found in that many measurements — which is
//! evidence, not proof, and says nothing of other machines or compilers.
//!
//! What a check must not reveal is how a forgery is wrong: a MAC or tag
//! compared byte by byte, stopping at the first difference, tells a forger
//! how many bytes it has right. So each comparison is timed on wrong values
//! that differ from the right one at the first byte against at a random
//! byte. Measured: `subtle`'s comparison itself, the receiver's mac1 check
//! of every datagram, cookies (mac2), the relay's proofs and tags, the AEADs'
//! tag checks, and the rejection of a forged transport packet whatever its
//! header unmasks to; and reading the private key out of the identity file,
//! one key against random keys. Whether a MAC is valid is not secret — what
//! happens next shows it — and where a check takes longer for a valid one,
//! that is reported, not held against it.
//!
//! And a control, which must be found: a comparison that stops at the
//! first differing byte. A harness that found nothing there would prove
//! nothing anywhere.
//!
//! ```text
//! cargo test --release --lib dudect -- --ignored --nocapture --test-threads=1
//! ```
//!
//! (`taskset -c N` in front keeps it on one core. The results of a run are
//! in `docs/evidence/crypto/dudect.log`.)

use rand::rngs::ThreadRng;
use rand::{Rng, RngCore};
use std::hint::black_box;
use std::time::Instant;

/// The dudect paper's threshold for |t|.
const THRESHOLD: f64 = 4.5;

/// Welch's t between two samples.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let stats = |x: &[f64]| {
        let n = x.len() as f64;
        let mean = x.iter().sum::<f64>() / n;
        let var = x.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (n, mean, var)
    };
    let (na, ma, va) = stats(a);
    let (nb, mb, vb) = stats(b);
    (ma - mb) / (va / na + vb / nb).sqrt()
}

/// What a measurement found: the largest |t| over the whole sample and
/// over samples cropped at several percentiles (dudect's way of cutting
/// away interrupts and other noise, which only ever make a run longer),
/// and how far apart the medians are.
pub struct Verdict {
    pub name: &'static str,
    pub measurements: usize,
    pub max_t: f64,
    pub at: String,
    pub medians: (f64, f64),
}

impl Verdict {
    pub fn leaks(&self) -> bool {
        self.max_t > THRESHOLD
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:<62} {:>8} runs  medians {:>7.0} / {:>7.0} ns  max |t| {:>8.2} ({})  {}",
            self.name,
            self.measurements,
            self.medians.0,
            self.medians.1,
            self.max_t,
            self.at,
            if self.leaks() {
                "DIFFERS"
            } else {
                "no difference found"
            }
        )
    }
}

fn median(sorted: &[f64]) -> f64 {
    sorted[sorted.len() / 2]
}

/// Inputs made at a time, before any of them is measured.
const CHUNK: usize = 10_000;

/// Times `op` on inputs made by `input(class)`, the class drawn at random
/// for each. The inputs are made in chunks before the clock starts on any
/// of them, as dudect does: made one by one just before each measurement,
/// what making an input of one class does to the processor's state (the
/// other class draws another random number, writes elsewhere) showed in
/// the measurement right after it, for operations of a few nanoseconds. A
/// measurement is `batch` runs of `op` on the same input.
pub fn measure<I>(
    name: &'static str,
    measurements: usize,
    batch: usize,
    mut input: impl FnMut(bool, &mut ThreadRng) -> I,
    mut op: impl FnMut(&mut I),
) -> Verdict {
    let mut rng = rand::thread_rng();
    // Warm the caches and the branch predictors on both classes first.
    for i in 0..(measurements / 20).min(CHUNK) {
        let mut x = input(i % 2 == 0, &mut rng);
        op(&mut x);
    }
    let mut times: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
    let mut done = 0;
    while done < measurements {
        let n = CHUNK.min(measurements - done);
        let mut inputs: Vec<(bool, I)> = (0..n)
            .map(|_| {
                let class: bool = rng.gen();
                (class, input(class, &mut rng))
            })
            .collect();
        for (class, x) in &mut inputs {
            let t0 = Instant::now();
            for _ in 0..batch {
                op(x);
            }
            times[*class as usize].push(t0.elapsed().as_nanos() as f64);
        }
        done += n;
    }
    for t in &mut times {
        t.sort_by(|a, b| a.partial_cmp(b).unwrap());
    }
    let mut all: Vec<f64> = times.iter().flatten().copied().collect();
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut max_t = 0.0f64;
    let mut at = String::from("whole");
    for pct in [100.0, 99.9, 99.0, 95.0, 90.0, 80.0, 70.0, 60.0, 50.0] {
        let cut = all[((all.len() - 1) as f64 * pct / 100.0) as usize];
        let a: Vec<f64> = times[0].iter().copied().filter(|t| *t <= cut).collect();
        let b: Vec<f64> = times[1].iter().copied().filter(|t| *t <= cut).collect();
        if a.len() < 1000 || b.len() < 1000 {
            continue;
        }
        let t = welch_t(&a, &b).abs();
        if t > max_t {
            max_t = t;
            at = if pct == 100.0 {
                "whole".to_string()
            } else {
                format!("below the {}th percentile", pct)
            };
        }
    }
    Verdict {
        name,
        measurements,
        max_t,
        at,
        medians: (
            median(&times[0]) / batch as f64,
            median(&times[1]) / batch as f64,
        ),
    }
}

/// `good` with one byte of `range` changed: the first byte of the range
/// (class false) or a random one (class true).
fn wrong_at(
    good: &[u8],
    range: std::ops::Range<usize>,
    anywhere: bool,
    rng: &mut ThreadRng,
) -> Vec<u8> {
    let mut b = good.to_vec();
    let pos = if anywhere {
        rng.gen_range(range)
    } else {
        range.start
    };
    b[pos] ^= 1 << rng.gen_range(0..8);
    b
}

fn random_bytes(len: usize, rng: &mut ThreadRng) -> Vec<u8> {
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::transport::{begin_packet, DirectionKeys, Suite, HEADER_LEN};
    use crate::crypto::{handshake, no_psk, Identity};

    const N: usize = 1_000_000;

    fn report(v: Verdict) -> Verdict {
        println!("{}", v);
        v
    }

    /// The control: a comparison that returns at the first differing byte
    /// is found out.
    #[test]
    #[ignore]
    fn dudect_finds_an_early_exit_comparison() {
        fn early_exit(a: &[u8], b: &[u8]) -> bool {
            for (x, y) in a.iter().zip(b) {
                if x != y {
                    return false;
                }
            }
            true
        }
        let a = random_bytes(64, &mut rand::thread_rng());
        let v = report(measure(
            "control: comparison stopping at the first difference",
            N,
            16,
            |anywhere, rng| wrong_at(&a, 0..64, anywhere, rng),
            |b| {
                black_box(early_exit(black_box(&a), black_box(b)));
            },
        ));
        assert!(v.leaks(), "the harness does not see an obvious leak: {}", v);
    }

    #[test]
    #[ignore]
    fn dudect_mac_comparison() {
        use subtle::ConstantTimeEq;
        let a = random_bytes(16, &mut rand::thread_rng());
        let v = report(measure(
            "subtle::ConstantTimeEq on 16 bytes",
            N,
            16,
            |anywhere, rng| wrong_at(&a, 0..16, anywhere, rng),
            |b| {
                black_box(bool::from(black_box(&a[..]).ct_eq(black_box(b))));
            },
        ));
        assert!(!v.leaks(), "{}", v);
    }

    /// The first thing a receiver does with every datagram: mac1.
    #[test]
    #[ignore]
    fn dudect_mac1() {
        let (s, r) = (Identity::generate(), Identity::generate());
        let responder = handshake::Responder::new(r.clone(), no_psk());
        let mut init = handshake::Initiator::new(&s, &r.id(), &no_psk()).unwrap();
        let good = init.initiation(&[0u8; 100], None).unwrap();
        let mac1 = good.len() - 32..good.len() - 16;
        let v = report(measure(
            "mac1 check, wrong at the first byte / anywhere",
            N / 4,
            1,
            |anywhere, rng| wrong_at(&good, mac1.clone(), anywhere, rng),
            |pkt| {
                black_box(responder.is_initiation(black_box(pkt)));
            },
        ));
        assert!(!v.leaks(), "{}", v);
        report(measure(
            "  (reported only) mac1 check, valid / invalid",
            N / 4,
            1,
            |invalid, rng| {
                if invalid {
                    wrong_at(&good, mac1.clone(), true, rng)
                } else {
                    good.clone()
                }
            },
            |pkt| {
                black_box(responder.is_initiation(black_box(pkt)));
            },
        ));
    }

    /// A cookie (mac2), checked against both of the jar's secrets.
    #[test]
    #[ignore]
    fn dudect_mac2() {
        let (s, r) = (Identity::generate(), Identity::generate());
        let mut jar = handshake::CookieJar::new(&r.id());
        let from: std::net::SocketAddr = "192.0.2.7:4000".parse().unwrap();
        let now = std::time::Instant::now();
        let mut init = handshake::Initiator::new(&s, &r.id(), &no_psk()).unwrap();
        let first = init.initiation(&[0u8; 100], None).unwrap();
        let reply = jar.reply(&first, from, now).unwrap();
        let cookie = init.read_cookie_reply(&reply).unwrap();
        let mut retry = handshake::Initiator::new(&s, &r.id(), &no_psk()).unwrap();
        let good = retry.initiation(&[0u8; 100], Some(&cookie)).unwrap();
        assert!(jar.mac2_ok(&good, from, now));
        let mac2 = good.len() - 16..good.len();
        let v = report(measure(
            "mac2 (cookie) check, wrong at the first byte / anywhere",
            N / 4,
            1,
            |anywhere, rng| wrong_at(&good, mac2.clone(), anywhere, rng),
            |pkt| {
                black_box(jar.mac2_ok(black_box(pkt), from, now));
            },
        ));
        assert!(!v.leaks(), "{}", v);
        // A valid cookie of the current secret is found at the first of the
        // two; an invalid one is tried against both. Which it is, the sender
        // learns anyway from what comes back.
        report(measure(
            "  (reported only) mac2 check, valid / invalid",
            N / 4,
            1,
            |invalid, rng| {
                if invalid {
                    wrong_at(&good, mac2.clone(), true, rng)
                } else {
                    good.clone()
                }
            },
            |pkt| {
                black_box(jar.mac2_ok(black_box(pkt), from, now));
            },
        ));
    }

    /// The relay's proofs (registrations) and tags (to a receiver).
    #[cfg(feature = "nat-traversal")]
    #[test]
    #[ignore]
    fn dudect_relay_proofs_and_tags() {
        let key = crate::crypto::SecretKey::random();
        let nonce = [7u8; 16];
        let body = random_bytes(120, &mut rand::thread_rng());
        let mut proven = body.clone();
        proven.extend_from_slice(&crate::relay::proof_for(&key, &body));
        let mut tagged = body.clone();
        tagged.extend_from_slice(&crate::relay::relay_tag(&key, &nonce, &body));
        let last = |p: &Vec<u8>| p.len() - 16..p.len();
        let v = report(measure(
            "relay proof, wrong at the first byte / anywhere",
            N / 4,
            1,
            |anywhere, rng| wrong_at(&proven, last(&proven), anywhere, rng),
            |pkt| {
                black_box(crate::relay::proof_is_good(&key, black_box(pkt)));
            },
        ));
        assert!(!v.leaks(), "{}", v);
        let v = report(measure(
            "relay tag, wrong at the first byte / anywhere",
            N / 4,
            1,
            |anywhere, rng| wrong_at(&tagged, last(&tagged), anywhere, rng),
            |pkt| {
                black_box(crate::relay::relay_tag_is_good(
                    &key,
                    &nonce,
                    black_box(pkt),
                ));
            },
        ));
        assert!(!v.leaks(), "{}", v);
    }

    /// The AEADs' own tag checks, asked directly (through a transport
    /// packet a changed tag would change the header it unmasks as well:
    /// the tag is header protection's sample).
    #[test]
    #[ignore]
    fn dudect_aead_tags() {
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        let nonce = [9u8; 12];
        let body = random_bytes(1200, &mut rand::thread_rng());
        let aes = aes_gcm::Aes256Gcm::new(&[5u8; 32].into());
        let chacha = chacha20poly1305::ChaCha20Poly1305::new(&[5u8; 32].into());
        let mut aes_ct = body.clone();
        let aes_tag = aes
            .encrypt_in_place_detached(&nonce.into(), b"ad", &mut aes_ct)
            .unwrap();
        let mut chacha_ct = body.clone();
        let chacha_tag = chacha
            .encrypt_in_place_detached(&nonce.into(), b"ad", &mut chacha_ct)
            .unwrap();
        let v = report(measure(
            "AES-256-GCM tag, wrong at the first byte / anywhere",
            N / 4,
            1,
            |anywhere, rng| (aes_ct.clone(), wrong_at(&aes_tag, 0..16, anywhere, rng)),
            |(ct, tag)| {
                black_box(
                    aes.decrypt_in_place_detached(&nonce.into(), b"ad", ct, tag[..].into())
                        .is_err(),
                );
            },
        ));
        assert!(!v.leaks(), "{}", v);
        let v = report(measure(
            "ChaCha20-Poly1305 tag, wrong at the first byte / anywhere",
            N / 4,
            1,
            |anywhere, rng| {
                (
                    chacha_ct.clone(),
                    wrong_at(&chacha_tag, 0..16, anywhere, rng),
                )
            },
            |(ct, tag)| {
                black_box(
                    chacha
                        .decrypt_in_place_detached(&nonce.into(), b"ad", ct, tag[..].into())
                        .is_err(),
                );
            },
        ));
        assert!(!v.leaks(), "{}", v);
    }

    /// A forged transport packet is rejected in the same time whatever its
    /// header unmasks to: one naming a kept epoch (a real packet with a
    /// byte of its body changed) against random ones, whose headers unmask
    /// to epochs nobody keeps. (Before keys were kept for a window of
    /// epochs, each of the latter cost a key derivation.)
    #[test]
    #[ignore]
    fn dudect_forged_packets() {
        for suite in [Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
            let tx = DirectionKeys::new(suite, &[3; 32]);
            let rx = DirectionKeys::new(suite, &[3; 32]);
            let mut real = Vec::new();
            begin_packet(&mut real, 9, 3, 1000);
            real.resize(HEADER_LEN + 1200, 0x5a);
            tx.seal(&mut real).unwrap();
            let n = real.len();
            let name = match suite {
                Suite::Aes256Gcm => "forged packet (AES-GCM), header of a kept epoch / random",
                Suite::ChaCha20Poly1305 => {
                    "forged packet (ChaCha20), header of a kept epoch / random"
                }
            };
            let v = report(measure(
                name,
                N / 8,
                1,
                |random, rng| {
                    if random {
                        let mut p = random_bytes(n, rng);
                        p[..8].copy_from_slice(&real[..8]);
                        p
                    } else {
                        wrong_at(&real, HEADER_LEN..n - 16, true, rng)
                    }
                },
                |pkt| {
                    black_box(rx.open(black_box(pkt)).is_err());
                },
            ));
            assert!(!v.leaks(), "{}", v);
        }
    }

    /// Reading the private key out of the identity file: one key against
    /// random keys. And `from_str_radix`, which picks each digit's value
    /// with a branch, for comparison (reported only).
    #[test]
    #[ignore]
    fn dudect_identity_file_hex() {
        use crate::crypto::identity::{hex_decode, hex_encode};
        let hex_of = |k: &[u8]| {
            let mut hex = vec![0u8; 64];
            hex_encode(k, &mut hex);
            hex
        };
        let fixed = hex_of(&random_bytes(32, &mut rand::thread_rng()));
        let mut out = [0u8; 32];
        let v = report(measure(
            "identity file hex, one key / random keys",
            N,
            8,
            |random, rng| {
                if random {
                    hex_of(&random_bytes(32, rng))
                } else {
                    fixed.clone()
                }
            },
            |text| {
                black_box(hex_decode(black_box(text), &mut out));
            },
        ));
        assert!(!v.leaks(), "{}", v);
        report(measure(
            "  (reported only) from_str_radix, one key / random keys",
            N,
            8,
            |random, rng| {
                if random {
                    hex_of(&random_bytes(32, rng))
                } else {
                    fixed.clone()
                }
            },
            |text| {
                for (j, byte) in out.iter_mut().enumerate() {
                    let pair = std::str::from_utf8(&text[2 * j..2 * j + 2]).unwrap();
                    *byte = u8::from_str_radix(black_box(pair), 16).unwrap();
                }
                black_box(&out);
            },
        ));
    }
}
