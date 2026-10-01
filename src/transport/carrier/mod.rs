//! Carriers other than UDP: the same datagrams, framed on a TCP stream, for
//! a network that blocks UDP or throttles it.
//!
//! **What changes, and what does not.** Nothing above the carrier knows it
//! is there. A datagram on a stream is exactly the datagram that would have
//! gone over UDP — sealed end to end, with its connection id and its packet
//! number — framed with its length ([`frame`]). A receiver accepts streams
//! at the TCP port with the number of its UDP port, and hands what they
//! carry to its dispatcher as if it had come in on its socket, from the
//! address the stream comes from ([`listen`]); what it sends to that
//! address goes back on the stream. A sender's engine sends to a *shim*, a
//! loopback socket that stands for the stream as a TURN client's shims
//! stand for the server ([`shim`]), so a stream is one more address to it,
//! tried by a handshake and moved to and from as any other: by proving it.
//!
//! **When.** A sender dials streams to the receiver when UDP has not
//! answered its first initiations within [`CARRIER_DELAY`], or has gone
//! quiet in the middle of a transfer ([`dial`]). A stream counts as a path
//! that is not direct, as a relay's port does: while the session runs on
//! one, the engine keeps asking the receiver's UDP addresses whether they
//! answer again, and goes back to UDP as soon as one does. UDP that answers
//! but is held back — policed to a trickle, or dropped in part — is found
//! out by a trial on a stream, and left for a while if TCP does better
//! ([`throttle`]).
//!
//! **How fast.** A stream is reliable and has congestion control of its
//! own; a session that ran its own over it as well would have both resend
//! what one of them only delayed, and the inner one back off on every stall
//! of the outer. So on a stream the engine sends whatever the stream has
//! room for (see `Engine::window`), unpaced, and its retransmission timer
//! only notices a stream that died.

pub mod dial;
pub mod frame;
pub mod link;
pub mod listen;
pub mod shim;
pub mod throttle;

pub use frame::MAX_DATAGRAM;
pub use link::{Link, StreamStats};
pub use listen::Streams;
pub use shim::Shims;

use std::time::Duration;

/// How long a sender waits for UDP to answer before it dials streams too.
pub const CARRIER_DELAY: Duration = Duration::from_millis(1500);

/// How much a stream may hold that is not yet written, before the engine
/// stops giving it more: enough to keep it busy between two turns of the
/// engine's loop at a gigabit, and a bound on what is resent when it dies.
pub const STREAM_ROOM: u64 = 1 << 20;
