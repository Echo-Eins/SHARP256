//! Finding a receiver on the local network without being told where it is.
//!
//! Two hosts on one network behind one NAT are often the hardest pair to
//! connect through the internet — many routers do not turn a packet sent to
//! their own outside address back inwards ("hairpinning") — and the easiest
//! to connect directly. A receiver that opts in announces itself with
//! multicast DNS (RFC 6762) and DNS-based service discovery (RFC 6763): a
//! service `_sharp256._udp.local.` whose instance is named by its SHARP ID,
//! with the port and the host's addresses. A sender that knows the ID and
//! opts in asks for exactly that instance, once, and gets the addresses to
//! try. Nothing here is trusted: what comes back is a list of addresses to
//! try, like every other, and the handshake decides who answers.
//!
//! Both sides are opt-in. An announcement tells everybody on the network that
//! this host receives SHARP-256 transfers, and a question tells them whom the
//! sender is looking for; the rest of the protocol takes pains to say
//! nothing to strangers, and the local network is full of them.
//!
//! What is implemented is the part this needs, not a resolver: names with
//! compression on the way in and without on the way out, the record types A,
//! AAAA, PTR, SRV and TXT, one-shot queries from an ephemeral port (which
//! RFC 6762 section 6.7 answers by unicast) and a responder that answers
//! them. Questions from beyond the link are ignored (section 11), and so is
//! anything past a small rate.

use crate::crypto::SharpId;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// The service every announcement is made under.
pub const SERVICE: &str = "_sharp256._udp.local.";
const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const PORT: u16 = 5353;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
/// In a question: an answer by unicast is welcome. In a record: the cache
/// may drop older records of this name and type.
const HIGH_BIT: u16 = 0x8000;
/// Records kept from one message, per section, and the longest name: all a
/// packet from a stranger is allowed to make us hold.
const MAX_RECORDS: usize = 64;
const MAX_NAME: usize = 255;
/// Compression pointers followed in one name.
const MAX_JUMPS: usize = 16;
/// Lifetime of what an announcement says, in seconds (RFC 6762's 75 minutes
/// for a host record would be long for an address that may change).
const TTL: u32 = 120;

/// What a record says, for the types this uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    Srv { port: u16, target: String },
    Txt(Vec<String>),
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Lower case, dot-terminated.
    pub name: String,
    pub class: u16,
    pub ttl: u32,
    pub data: Data,
}

impl Record {
    fn rtype(&self) -> u16 {
        match self.data {
            Data::A(_) => TYPE_A,
            Data::Aaaa(_) => TYPE_AAAA,
            Data::Ptr(_) => TYPE_PTR,
            Data::Srv { .. } => TYPE_SRV,
            Data::Txt(_) => TYPE_TXT,
            Data::Other => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub additionals: Vec<Record>,
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

fn put_name(out: &mut Vec<u8>, name: &str) -> bool {
    let trimmed = name.trim_end_matches('.');
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    true
}

/// Reads a name at `pos`, following compression pointers. Returns it in
/// lower case with a trailing dot, and where the name ended *in the place it
/// was first read* (after its pointer, if it began with one).
fn take_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos)? as usize;
        match len {
            0 => {
                pos += 1;
                break;
            }
            l if l & 0xc0 == 0xc0 => {
                let low = *buf.get(pos + 1)? as usize;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None;
                }
                pos = ((l & 0x3f) << 8) | low;
            }
            l if l & 0xc0 != 0 => return None,
            l => {
                let label = buf.get(pos + 1..pos + 1 + l)?;
                if name.len() + l + 1 > MAX_NAME {
                    return None;
                }
                name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
                name.push('.');
                pos += 1 + l;
            }
        }
    }
    if name.is_empty() {
        name.push('.');
    }
    Some((name, end.unwrap_or(pos)))
}

fn take_u16(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes(buf.get(pos..pos + 2)?.try_into().ok()?))
}

fn take_record(buf: &[u8], pos: &mut usize) -> Option<Record> {
    let (name, at) = take_name(buf, *pos)?;
    let rtype = take_u16(buf, at)?;
    let class = take_u16(buf, at + 2)?;
    let ttl = u32::from_be_bytes(buf.get(at + 4..at + 8)?.try_into().ok()?);
    let len = take_u16(buf, at + 8)? as usize;
    let start = at + 10;
    let rdata = buf.get(start..start + len)?;
    *pos = start + len;
    let data = match rtype {
        TYPE_A if len == 4 => Data::A(Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?)),
        TYPE_AAAA if len == 16 => Data::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?)),
        TYPE_PTR => Data::Ptr(take_name(buf, start)?.0),
        TYPE_SRV if len >= 7 => Data::Srv {
            port: take_u16(buf, start + 4)?,
            target: take_name(buf, start + 6)?.0,
        },
        TYPE_TXT => {
            let mut out = Vec::new();
            let mut p = 0;
            while p < rdata.len() {
                let l = rdata[p] as usize;
                out.push(String::from_utf8_lossy(rdata.get(p + 1..p + 1 + l)?).into_owned());
                p += 1 + l;
            }
            Data::Txt(out)
        }
        _ => Data::Other,
    };
    Some(Record {
        name,
        class: class & !HIGH_BIT,
        ttl,
        data,
    })
}

impl Message {
    /// Reads a message. Anything malformed, or bigger than what one is
    /// allowed to make us hold, is refused whole.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        let id = take_u16(buf, 0)?;
        let flags = take_u16(buf, 2)?;
        let (qd, an, ns, ar) = (
            take_u16(buf, 4)? as usize,
            take_u16(buf, 6)? as usize,
            take_u16(buf, 8)? as usize,
            take_u16(buf, 10)? as usize,
        );
        if qd > MAX_RECORDS || an > MAX_RECORDS || ns > MAX_RECORDS || ar > MAX_RECORDS {
            return None;
        }
        let mut pos = 12;
        let mut questions = Vec::with_capacity(qd);
        for _ in 0..qd {
            let (name, at) = take_name(buf, pos)?;
            questions.push(Question {
                name,
                qtype: take_u16(buf, at)?,
                class: take_u16(buf, at + 2)?,
            });
            pos = at + 4;
        }
        let mut answers = Vec::with_capacity(an);
        for _ in 0..an {
            answers.push(take_record(buf, &mut pos)?);
        }
        for _ in 0..ns {
            take_record(buf, &mut pos)?;
        }
        let mut additionals = Vec::with_capacity(ar);
        for _ in 0..ar {
            additionals.push(take_record(buf, &mut pos)?);
        }
        Some(Self {
            id,
            response: flags & 0x8000 != 0,
            questions,
            answers,
            additionals,
        })
    }

    /// The message as a packet. `None` for a name that cannot be written.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.id.to_be_bytes());
        // A response is authoritative (0x0400); a query has no flags.
        out.extend_from_slice(&(if self.response { 0x8400u16 } else { 0 }).to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());
        for q in &self.questions {
            if !put_name(&mut out, &q.name) {
                return None;
            }
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.class.to_be_bytes());
        }
        for r in self.answers.iter().chain(&self.additionals) {
            if !put_name(&mut out, &r.name) {
                return None;
            }
            out.extend_from_slice(&r.rtype().to_be_bytes());
            out.extend_from_slice(&(r.class | HIGH_BIT).to_be_bytes());
            out.extend_from_slice(&r.ttl.to_be_bytes());
            let mut data = Vec::new();
            match &r.data {
                Data::A(a) => data.extend_from_slice(&a.octets()),
                Data::Aaaa(a) => data.extend_from_slice(&a.octets()),
                Data::Ptr(n) => {
                    if !put_name(&mut data, n) {
                        return None;
                    }
                }
                Data::Srv { port, target } => {
                    data.extend_from_slice(&[0, 0, 0, 0]);
                    data.extend_from_slice(&port.to_be_bytes());
                    if !put_name(&mut data, target) {
                        return None;
                    }
                }
                Data::Txt(strings) => {
                    for s in strings {
                        if s.len() > 255 {
                            return None;
                        }
                        data.push(s.len() as u8);
                        data.extend_from_slice(s.as_bytes());
                    }
                    if strings.is_empty() {
                        data.push(0);
                    }
                }
                Data::Other => return None,
            }
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(&data);
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// The instance name of a receiver: its ID, which is 59 characters, in a
/// label of at most 63.
pub fn instance_name(id: &SharpId) -> String {
    format!("{}.{}", id.to_string().to_ascii_lowercase(), SERVICE)
}

/// The name of a receiver's host in `.local`: derived from its ID, so that
/// two receivers on one network never collide and no real host name leaks.
pub fn host_name(id: &SharpId) -> String {
    format!(
        "sharp-{}.local.",
        &id.to_string()[3..3 + 12].to_ascii_lowercase()
    )
}

/// The question a sender asks: the instance of one receiver, any record, an
/// answer by unicast welcome.
pub fn query_for(id: &SharpId) -> Message {
    Message {
        questions: vec![Question {
            name: instance_name(id),
            qtype: TYPE_ANY,
            class: CLASS_IN | HIGH_BIT,
        }],
        ..Message::default()
    }
}

// ---------------------------------------------------------------------------
// Answering
// ---------------------------------------------------------------------------

/// What this host says about itself.
#[derive(Debug, Clone)]
pub struct Announcement {
    pub id: SharpId,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

impl Announcement {
    /// The answer to `query`, if it asks about this receiver: the PTR for
    /// the service, the SRV and TXT of the instance with the addresses
    /// alongside, or the addresses of the host name.
    pub fn answer(&self, query: &Message) -> Option<Message> {
        if query.response {
            return None;
        }
        let instance = instance_name(&self.id);
        let host = host_name(&self.id);
        let mut out = Message {
            id: 0,
            response: true,
            ..Message::default()
        };
        let ptr = Record {
            name: SERVICE.to_string(),
            class: CLASS_IN,
            ttl: TTL,
            data: Data::Ptr(instance.clone()),
        };
        let srv = Record {
            name: instance.clone(),
            class: CLASS_IN,
            ttl: TTL,
            data: Data::Srv {
                port: self.port,
                target: host.clone(),
            },
        };
        let txt = Record {
            name: instance.clone(),
            class: CLASS_IN,
            ttl: TTL,
            data: Data::Txt(vec!["v=1".to_string()]),
        };
        let addresses: Vec<Record> = self
            .addresses
            .iter()
            .map(|ip| Record {
                name: host.clone(),
                class: CLASS_IN,
                ttl: TTL,
                data: match ip {
                    IpAddr::V4(a) => Data::A(*a),
                    IpAddr::V6(a) => Data::Aaaa(*a),
                },
            })
            .collect();
        let wants = |name: &str, types: &[u16]| {
            query
                .questions
                .iter()
                .any(|q| q.name == name && (q.qtype == TYPE_ANY || types.contains(&q.qtype)))
        };
        if wants(SERVICE, &[TYPE_PTR]) {
            out.answers.push(ptr);
            out.additionals.push(srv.clone());
            out.additionals.push(txt.clone());
            out.additionals.extend(addresses.clone());
        } else if wants(&instance, &[TYPE_SRV, TYPE_TXT]) {
            out.answers.push(srv);
            out.answers.push(txt);
            out.additionals.extend(addresses);
        } else if wants(&host, &[TYPE_A, TYPE_AAAA]) {
            out.answers.extend(addresses.into_iter().filter(|r| {
                query.questions.iter().any(|q| {
                    q.name == host
                        && (q.qtype == TYPE_ANY
                            || (q.qtype == TYPE_A && matches!(r.data, Data::A(_)))
                            || (q.qtype == TYPE_AAAA && matches!(r.data, Data::Aaaa(_))))
                })
            }));
        }
        if out.answers.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

/// The addresses of a response to [`query_for`] `id`: where the instance's
/// SRV record says the receiver is, as `port` at each address the host name
/// resolves to.
pub fn addresses_in(response: &Message, id: &SharpId) -> Vec<(IpAddr, u16)> {
    if !response.response {
        return Vec::new();
    }
    let instance = instance_name(id);
    let records: Vec<&Record> = response
        .answers
        .iter()
        .chain(&response.additionals)
        .collect();
    let mut out = Vec::new();
    for srv in records.iter().filter(|r| r.name == instance) {
        let Data::Srv { port, target } = &srv.data else {
            continue;
        };
        for r in records.iter().filter(|r| &r.name == target) {
            let ip = match r.data {
                Data::A(a) => IpAddr::V4(a),
                Data::Aaaa(a) => IpAddr::V6(a),
                _ => continue,
            };
            if *port != 0 && !out.contains(&(ip, *port)) && out.len() < 8 {
                out.push((ip, *port));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The network
// ---------------------------------------------------------------------------

/// One interface worth using: its name, index and addresses.
#[derive(Debug, Clone)]
struct Iface {
    index: u32,
    v4: Vec<(Ipv4Addr, Ipv4Addr)>,
    v6: Vec<Ipv6Addr>,
}

fn interfaces() -> Vec<Iface> {
    let Ok(all) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut out: Vec<Iface> = Vec::new();
    for i in all {
        if i.is_loopback() {
            continue;
        }
        let Some(index) = crate::address::dns::interface_index_of(&i.name) else {
            continue;
        };
        let entry = match out.iter().position(|e| e.index == index) {
            Some(p) => &mut out[p],
            None => {
                out.push(Iface {
                    index,
                    v4: Vec::new(),
                    v6: Vec::new(),
                });
                out.last_mut().expect("just pushed")
            }
        };
        match i.addr {
            if_addrs::IfAddr::V4(a) => entry.v4.push((a.ip, a.netmask)),
            if_addrs::IfAddr::V6(a) => entry.v6.push(a.ip),
        }
    }
    out
}

/// Whether `from` is on a network this host is on: the only kind of source
/// a multicast-DNS question may come from (RFC 6762 section 11).
fn on_link(from: IpAddr, ifaces: &[Iface]) -> bool {
    match crate::address::canonical(SocketAddr::new(from, 0)).ip() {
        IpAddr::V4(v4) => ifaces.iter().any(|i| {
            i.v4.iter().any(|(ip, mask)| {
                let m = u32::from(*mask);
                m != 0 && (u32::from(v4) & m) == (u32::from(*ip) & m)
            })
        }),
        IpAddr::V6(v6) => {
            crate::address::class::is_link_local_v6(&v6)
                || ifaces.iter().any(|i| {
                    i.v6.iter()
                        .any(|ip| ip.segments()[..4] == v6.segments()[..4])
                })
        }
    }
}

fn reusable_socket(v6: bool) -> io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(
        if v6 { Domain::IPV6 } else { Domain::IPV4 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    s.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    s.set_reuse_port(true)?;
    if v6 {
        s.set_only_v6(true)?;
    }
    s.set_nonblocking(true)?;
    Ok(s)
}

/// Announces `announcement` on every local network until `cancel` fires.
///
/// The answers go by unicast to whoever asked, from the socket the question
/// arrived on, which is what a one-shot question from an ephemeral port
/// gets (RFC 6762 section 6.7). At most a few a second, and only to
/// sources on the link: this port is open to the whole network, and a
/// responder that answered anyone would be a small reflector.
pub fn announce(
    announcement: impl Fn() -> Announcement + Send + Sync + 'static,
    cancel: CancellationToken,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let ifaces = interfaces();
    let mut sockets: Vec<Arc<UdpSocket>> = Vec::new();
    let v4 = reusable_socket(false)?;
    v4.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT)).into())?;
    for i in &ifaces {
        for (ip, _) in &i.v4 {
            let _ = v4.join_multicast_v4(&GROUP_V4, ip);
        }
    }
    sockets.push(Arc::new(UdpSocket::from_std(v4.into())?));
    if let Ok(v6) = reusable_socket(true) {
        if v6
            .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, PORT)).into())
            .is_ok()
        {
            for i in &ifaces {
                let _ = v6.join_multicast_v6(&GROUP_V6, i.index);
            }
            sockets.push(Arc::new(UdpSocket::from_std(v6.into())?));
        }
    }
    let announcement = Arc::new(announcement);
    Ok(tokio::spawn(async move {
        let (tx, mut rx) = mpsc::channel::<(Arc<UdpSocket>, Vec<u8>, SocketAddr)>(64);
        for s in &sockets {
            let (s, tx, cancel) = (s.clone(), tx.clone(), cancel.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1500];
                loop {
                    let r = tokio::select! {
                        r = s.recv_from(&mut buf) => r,
                        _ = cancel.cancelled() => return,
                    };
                    if let Ok((n, from)) = r {
                        if tx.send((s.clone(), buf[..n].to_vec(), from)).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
        drop(tx);
        // A few answers a second: enough for anyone looking, too little to
        // be worth abusing.
        let mut allowance = 10.0f64;
        let mut at = Instant::now();
        loop {
            let (socket, data, from) = tokio::select! {
                m = rx.recv() => match m {
                    Some(m) => m,
                    None => return,
                },
                _ = cancel.cancelled() => return,
            };
            let now = Instant::now();
            allowance =
                (allowance + now.saturating_duration_since(at).as_secs_f64() * 5.0).min(10.0);
            at = now;
            let Some(query) = Message::decode(&data) else {
                continue;
            };
            if query.response || query.questions.is_empty() {
                continue;
            }
            let ann = announcement();
            let Some(answer) = ann.answer(&query) else {
                continue;
            };
            if !on_link(from.ip(), &interfaces()) || allowance < 1.0 {
                continue;
            }
            allowance -= 1.0;
            if let Some(bytes) = answer.encode() {
                let _ = socket.send_to(&bytes, from).await;
            }
        }
    }))
}

/// Asks the local networks for the receiver `id`, and returns where they say
/// it is, for at most `wait`. The question is repeated a couple of times,
/// as RFC 6762 section 5.2 asks of a one-shot query.
pub async fn find(id: &SharpId, wait: Duration) -> Vec<SocketAddr> {
    let Some(query) = query_for(id).encode() else {
        return Vec::new();
    };
    let ifaces = interfaces();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr, u32)>(64);
    let mut sockets: Vec<(Arc<UdpSocket>, SocketAddr)> = Vec::new();
    for i in &ifaces {
        if let Some((ip, _)) = i.v4.first() {
            if let Ok(s) = reusable_socket(false) {
                let ok = s
                    .bind(&SocketAddr::from((*ip, 0)).into())
                    .and_then(|_| s.set_multicast_if_v4(ip))
                    .and_then(|_| s.set_multicast_ttl_v4(255))
                    .and_then(|_| s.set_multicast_loop_v4(false));
                if ok.is_ok() {
                    if let Ok(u) = UdpSocket::from_std(s.into()) {
                        sockets.push((Arc::new(u), SocketAddr::from((GROUP_V4, PORT))));
                        spawn_reader(sockets.last().expect("pushed").0.clone(), i.index, &tx);
                    }
                }
            }
        }
        if i.v6.iter().any(crate::address::class::is_link_local_v6) {
            if let Ok(s) = reusable_socket(true) {
                let ok = s
                    .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
                    .and_then(|_| s.set_multicast_if_v6(i.index))
                    .and_then(|_| s.set_multicast_hops_v6(255))
                    .and_then(|_| s.set_multicast_loop_v6(false));
                if ok.is_ok() {
                    if let Ok(u) = UdpSocket::from_std(s.into()) {
                        let to = SocketAddr::V6(SocketAddrV6::new(GROUP_V6, PORT, 0, i.index));
                        sockets.push((Arc::new(u), to));
                        spawn_reader(sockets.last().expect("pushed").0.clone(), i.index, &tx);
                    }
                }
            }
        }
    }
    drop(tx);
    if sockets.is_empty() {
        return Vec::new();
    }
    let deadline = tokio::time::Instant::now() + wait;
    let mut found: Vec<SocketAddr> = Vec::new();
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let mut next_ask = tokio::time::Instant::now();
    let mut asked = 0;
    loop {
        if asked < 3 && tokio::time::Instant::now() >= next_ask {
            for (s, to) in &sockets {
                let _ = s.send_to(&query, *to).await;
            }
            asked += 1;
            next_ask = tokio::time::Instant::now() + Duration::from_millis(400 * asked as u64);
        }
        let until = deadline.min(next_ask);
        match tokio::time::timeout_at(until, rx.recv()).await {
            Ok(Some((data, _from, index))) => {
                let Some(msg) = Message::decode(&data) else {
                    continue;
                };
                for (ip, port) in addresses_in(&msg, id) {
                    // A link-local address means the interface it was
                    // heard on.
                    let addr = match ip {
                        IpAddr::V6(v6) if crate::address::class::is_link_local_v6(&v6) => {
                            SocketAddr::V6(SocketAddrV6::new(v6, port, 0, index))
                        }
                        ip => SocketAddr::new(ip, port),
                    };
                    if seen.insert(addr) {
                        found.push(addr);
                    }
                }
                // Enough: the rest of the wait would only add copies.
                if !found.is_empty() {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
            }
        }
    }
    found
}

fn spawn_reader(socket: Arc<UdpSocket>, index: u32, tx: &mpsc::Sender<(Vec<u8>, SocketAddr, u32)>) {
    let tx = tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            if tx.send((buf[..n].to_vec(), from, index)).await.is_err() {
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    fn announcement() -> Announcement {
        Announcement {
            id: Identity::generate().id(),
            port: 5555,
            addresses: vec![
                "192.168.1.7".parse().unwrap(),
                "fe80::1234".parse().unwrap(),
            ],
        }
    }

    /// What a sender asks and what a receiver answers survive the wire, and
    /// the sender comes away with the port at each of the addresses.
    #[test]
    fn a_question_gets_the_receivers_addresses() {
        let ann = announcement();
        let q = query_for(&ann.id);
        let q = Message::decode(&q.encode().unwrap()).unwrap();
        let a = ann.answer(&q).expect("it is asked about");
        let a = Message::decode(&a.encode().unwrap()).unwrap();
        assert_eq!(
            addresses_in(&a, &ann.id),
            vec![
                ("192.168.1.7".parse().unwrap(), 5555),
                ("fe80::1234".parse().unwrap(), 5555)
            ]
        );
    }

    /// Only the receiver asked about answers, and only about its own names:
    /// another instance, another service, and a response are all silence.
    #[test]
    fn a_receiver_answers_only_questions_about_itself() {
        let ann = announcement();
        let other = Identity::generate().id();
        assert!(ann.answer(&query_for(&other)).is_none());
        let mut wrong = query_for(&ann.id);
        wrong.questions[0].name = "_http._tcp.local.".to_string();
        assert!(ann.answer(&wrong).is_none());
        let mut response = query_for(&ann.id);
        response.response = true;
        assert!(ann.answer(&response).is_none());
        // Browsing for the service finds it too.
        let browse = Message {
            questions: vec![Question {
                name: SERVICE.to_string(),
                qtype: TYPE_PTR,
                class: CLASS_IN,
            }],
            ..Message::default()
        };
        let a = ann.answer(&browse).expect("the service is announced");
        assert!(matches!(&a.answers[0].data, Data::Ptr(n) if *n == instance_name(&ann.id)));
        assert_eq!(addresses_in(&a, &ann.id).len(), 2);
        // And the host name resolves by itself.
        let host = Message {
            questions: vec![Question {
                name: host_name(&ann.id),
                qtype: TYPE_A,
                class: CLASS_IN,
            }],
            ..Message::default()
        };
        let a = ann.answer(&host).unwrap();
        assert_eq!(a.answers.len(), 1);
        assert!(matches!(a.answers[0].data, Data::A(_)));
    }

    /// Names arrive compressed from other implementations, and are read;
    /// pointers that loop or run off the end are refused.
    #[test]
    fn compressed_names_are_read_and_loops_are_not_followed() {
        // "b.local." then a name that is "a" followed by a pointer to it.
        let mut buf = vec![0u8; 12];
        let base = buf.len();
        buf.extend_from_slice(&[1, b'b', 5, b'l', b'o', b'c', b'a', b'l', 0]);
        let second = buf.len();
        buf.extend_from_slice(&[1, b'A', 0xc0, base as u8]);
        assert_eq!(take_name(&buf, base).unwrap().0, "b.local.");
        let (n, end) = take_name(&buf, second).unwrap();
        assert_eq!(n, "a.b.local.", "read in lower case");
        assert_eq!(end, second + 4);
        // A pointer at itself.
        let looping = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 12];
        assert!(take_name(&looping, 12).is_none());
        // One past the end.
        assert!(take_name(&[1, b'a'], 0).is_none());
    }

    #[test]
    fn what_a_stranger_sends_is_refused_or_bounded() {
        assert!(Message::decode(&[]).is_none());
        assert!(Message::decode(&[0; 11]).is_none());
        // Claims 65535 records.
        let mut huge = vec![0u8; 12];
        huge[6] = 0xff;
        huge[7] = 0xff;
        assert!(Message::decode(&huge).is_none());
        // Claims one and holds none.
        let mut short = vec![0u8; 12];
        short[5] = 1;
        assert!(Message::decode(&short).is_none());
        // Too long a name is not written either.
        let mut m = Message::default();
        m.questions.push(Question {
            name: format!("{}.local.", "a".repeat(64)),
            qtype: TYPE_A,
            class: CLASS_IN,
        });
        assert!(m.encode().is_none());
    }

    #[test]
    fn a_source_beyond_the_link_is_not_answered() {
        let ifaces = vec![Iface {
            index: 2,
            v4: vec![(
                "192.168.1.7".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
            )],
            v6: vec!["2001:db8:1:2::7".parse().unwrap()],
        }];
        assert!(on_link("192.168.1.99".parse().unwrap(), &ifaces));
        assert!(!on_link("192.168.2.1".parse().unwrap(), &ifaces));
        assert!(!on_link("203.0.113.9".parse().unwrap(), &ifaces));
        assert!(on_link("fe80::1".parse().unwrap(), &ifaces));
        assert!(on_link("2001:db8:1:2::99".parse().unwrap(), &ifaces));
        assert!(!on_link("2001:db8:9::1".parse().unwrap(), &ifaces));
        // An IPv4 source that came in on a dual-stack socket.
        assert!(on_link("::ffff:192.168.1.5".parse().unwrap(), &ifaces));
    }
}
