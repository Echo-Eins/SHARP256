//! TLS 1.3 to a relay: a way through for a network that lets little but
//! HTTPS out, which shows whether anything on the way opened it.
//!
//! **What TLS is for here.** Nothing inside depends on it: a transfer is
//! sealed end to end, and the relay's own messages carry their own proofs.
//! TLS is a way past a network that lets out only what looks like TLS, on
//! port 443. So the relay's certificate is checked against nobody's list of
//! authorities: it is a self-signed one the relay makes at start-up
//! ([`certificate`]), and a client takes whatever certificate it is shown —
//! checking only that the server holds that certificate's key.
//!
//! **What it must not do** is let something on the way open the session
//! unnoticed: a TLS-inspecting proxy, which ends the client's TLS with a
//! certificate of its own and opens another TLS session to the relay. The
//! two sessions are then not one, and the keys each end exports from its
//! own (RFC 8446 section 7.5) differ. So the first thing a client asks over
//! the stream is for the relay to prove its identity over the key it
//! exported: a MAC under a key that only the relay's long-term key and the
//! client's ephemeral one make ([`bind`]). A proxy in the middle cannot
//! make it, and the client refuses the stream — out loud: the network did
//! not merely fail, it is reading what goes through it ([`Intercepted`]).

pub use super::tunnel::{is_intercepted, Intercepted};
use crate::crypto::{Identity, SharpId};
use crate::transport::carrier::frame::{self, Frame, HEADER_LEN};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// What the binding's keys are exported under.
const BINDING_LABEL: &[u8] = b"EXPORTER-sharp256-relay-binding";
/// How long the relay has to prove itself.
const BINDING_WAIT: Duration = Duration::from_secs(5);
/// The messages of the binding: the client's ask, the relay's answer.
const ASK: u8 = 1;
const ANSWER: u8 = 2;
const NONCE_LEN: usize = 16;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// ---------------------------------------------------------------------------
// The relay's certificate
// ---------------------------------------------------------------------------

/// A DER element.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend([0x81, n as u8]);
    } else {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    der(0x30, &parts.concat())
}

/// A self-signed X.509 certificate for an Ed25519 key made now, and the key:
/// what a relay presents over TLS. Its name says what it is and nothing
/// about who runs it; it is good from 2020 to the end of 2049, and nothing
/// checks either.
pub fn certificate() -> io::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| io::Error::other("no key"))?;
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| io::Error::other("no key"))?;
    // Ed25519 (RFC 8410): the object identifier 1.3.101.112, no parameters.
    let ed25519 = seq(&[&der(0x06, &[0x2b, 0x65, 0x70])]);
    // The common name, 2.5.4.3.
    let name = seq(&[&der(
        0x31,
        &seq(&[
            &der(0x06, &[0x55, 0x04, 0x03]),
            &der(0x0c, b"sharp256 relay"),
        ]),
    )]);
    let validity = seq(&[&der(0x17, b"200101000000Z"), &der(0x17, b"491231235959Z")]);
    let mut serial: [u8; 16] = rand::Rng::gen(&mut rand::rngs::OsRng);
    // Positive, and no leading zero byte to make it longer than it is.
    serial[0] = (serial[0] & 0x7f) | 0x40;
    let mut public = vec![0u8];
    public.extend_from_slice(key.public_key().as_ref());
    let spki = seq(&[&ed25519, &der(0x03, &public)]);
    let tbs = seq(&[
        // Version 3, explicitly tagged [0].
        &der(0xa0, &der(0x02, &[2])),
        &der(0x02, &serial),
        &ed25519,
        &name,
        &validity,
        &name,
        &spki,
    ]);
    let mut signature = vec![0u8];
    signature.extend_from_slice(key.sign(&tbs).as_ref());
    let cert = seq(&[&tbs, &ed25519, &der(0x03, &signature)]);
    Ok((
        CertificateDer::from(cert),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec())),
    ))
}

/// What a relay speaks TLS with: TLS 1.3 alone, a certificate of its own.
pub fn server_config() -> io::Result<Arc<rustls::ServerConfig>> {
    let (cert, key) = certificate()?;
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(io::Error::other)?;
    Ok(Arc::new(config))
}

/// Takes whatever certificate a relay shows (see the module's account of
/// why), and only checks that the server holds its key.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Never asked: TLS 1.3 alone is spoken.
        Err(rustls::Error::General("TLS 1.2 is not spoken".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// What a client speaks TLS to a relay with.
pub fn client_config() -> io::Result<Arc<rustls::ClientConfig>> {
    let provider = provider();
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Binding the session to the relay's key
// ---------------------------------------------------------------------------

/// The relay's proof that a TLS session is its own: a MAC over the key
/// `exported` from the session, under a key from the two keys' exchange
/// and everything else the ask carried.
pub(crate) fn binding_mac(
    shared: &[u8],
    ephemeral: &[u8; 32],
    relay: &SharpId,
    nonce: &[u8],
    exported: &[u8; 32],
) -> [u8; 32] {
    let key = crate::crypto::derive_secret(
        "sharp256 relay tls binding v1",
        &[shared, ephemeral, relay.as_bytes(), nonce],
    );
    crate::crypto::keyed_mac(&key, &[exported])
}

/// The client's ask: its ephemeral public key and a nonce.
pub(crate) fn ask(ephemeral: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    [&[ASK][..], ephemeral, nonce].concat()
}

/// The relay's answer: the MAC.
pub(crate) fn answer(mac: &[u8; 32]) -> Vec<u8> {
    [&[ANSWER][..], mac].concat()
}

/// What the binding is made over: a key exported from the TLS session
/// (RFC 8446 section 7.5), which each end of one session has alike and the
/// ends of two different ones do not.
fn export<D>(conn: &rustls::ConnectionCommon<D>, nonce: &[u8]) -> io::Result<[u8; 32]> {
    conn.export_keying_material([0u8; 32], BINDING_LABEL, Some(nonce))
        .map_err(io::Error::other)
}

async fn write_own<S: AsyncWrite + Unpin>(stream: &mut S, body: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&frame::own_header(body.len()));
    out.extend_from_slice(body);
    stream.write_all(&out).await?;
    stream.flush().await
}

async fn read_own<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    match tokio::time::timeout(BINDING_WAIT, frame::read_frame(stream)).await {
        Ok(Ok(Some(Frame::Own(body)))) => Ok(body),
        Ok(Ok(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the relay did not prove itself",
        )),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the relay did not prove itself in time",
        )),
    }
}

/// The client's side: asks the relay `relay` to prove the TLS session on
/// `stream` is its own, and checks the answer. [`Intercepted`] when it is
/// not.
pub async fn bind(
    stream: &mut tokio_rustls::client::TlsStream<impl AsyncRead + AsyncWrite + Unpin>,
    relay: &SharpId,
) -> io::Result<()> {
    let ephemeral = Identity::generate();
    let nonce: [u8; NONCE_LEN] = rand::Rng::gen(&mut rand::rngs::OsRng);
    let shared = ephemeral.shared_secret(relay).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the relay's identity is not a usable key",
        )
    })?;
    let exporter = export(stream.get_ref().1, &nonce)?;
    write_own(stream, &ask(ephemeral.id().as_bytes(), &nonce)).await?;
    let answered = read_own(stream).await?;
    let expected = binding_mac(
        &shared[..],
        ephemeral.id().as_bytes(),
        relay,
        &nonce,
        &exporter,
    );
    if answered.len() == 33 && answered[0] == ANSWER && bool::from(answered[1..].ct_eq(&expected)) {
        return Ok(());
    }
    Err(io::Error::other(Intercepted))
}

/// The relay's side: answers a client's ask with the proof that the TLS
/// session on `stream` is its own, made with `identity`.
pub async fn prove(
    stream: &mut tokio_rustls::server::TlsStream<impl AsyncRead + AsyncWrite + Unpin>,
    identity: &Identity,
) -> io::Result<()> {
    let ask = read_own(stream).await?;
    if ask.len() != 1 + 32 + NONCE_LEN || ask[0] != ASK {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not an ask"));
    }
    let mut ephemeral = [0u8; 32];
    ephemeral.copy_from_slice(&ask[1..33]);
    let nonce = &ask[33..];
    // A key of small order makes a "shared" secret anyone can compute:
    // refused, as everywhere else keys are exchanged.
    let shared = identity
        .shared_secret(&SharpId::from_public(ephemeral))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "an unusable key"))?;
    let exporter = export(stream.get_ref().1, nonce)?;
    let mac = binding_mac(&shared[..], &ephemeral, &identity.id(), nonce, &exporter);
    write_own(stream, &answer(&mac)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn name() -> ServerName<'static> {
        ServerName::try_from("relay.example").unwrap()
    }

    #[test]
    fn the_certificate_is_one_tls_can_read() {
        let (cert, _) = certificate().unwrap();
        // What a client does with it: read it, as the signature check does.
        let parsed = webpki_parse(&cert);
        assert!(parsed, "the certificate does not parse");
    }

    fn webpki_parse(cert: &CertificateDer<'_>) -> bool {
        rustls::server::ParsedCertificate::try_from(cert).is_ok()
    }

    #[tokio::test]
    async fn a_relay_proves_the_session_is_its_own() {
        let relay = Identity::generate();
        let (client_io, server_io) = duplex(1 << 16);
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config().unwrap());
        let connector = tokio_rustls::TlsConnector::from(client_config().unwrap());
        let r = relay.clone();
        let server = tokio::spawn(async move {
            let mut s = acceptor.accept(server_io).await.unwrap();
            prove(&mut s, &r).await
        });
        let mut c = connector.connect(name(), client_io).await.unwrap();
        bind(&mut c, &relay.id())
            .await
            .expect("the relay's own session");
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_relay_that_is_not_the_one_named_does_not_prove_it() {
        let relay = Identity::generate();
        let (client_io, server_io) = duplex(1 << 16);
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config().unwrap());
        let connector = tokio_rustls::TlsConnector::from(client_config().unwrap());
        tokio::spawn(async move {
            let mut s = acceptor.accept(server_io).await.unwrap();
            let _ = prove(&mut s, &relay).await;
        });
        let mut c = connector.connect(name(), client_io).await.unwrap();
        let other = Identity::generate().id();
        let e = bind(&mut c, &other).await.unwrap_err();
        assert!(is_intercepted(&e), "{}", e);
    }

    /// A proxy that ends the client's TLS and opens its own to the relay,
    /// passing what is inside along: the relay answers, honestly, for the
    /// session it has — which is not the client's.
    #[tokio::test]
    async fn a_session_opened_on_the_way_is_found_out() {
        let relay = Identity::generate();
        let (client_io, proxy_front) = duplex(1 << 16);
        let (proxy_back, server_io) = duplex(1 << 16);
        let r = relay.clone();
        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config().unwrap());
            let mut s = acceptor.accept(server_io).await.unwrap();
            let _ = prove(&mut s, &r).await;
        });
        tokio::spawn(async move {
            // The proxy's own certificate to the client, and its own TLS to
            // the relay; bytes copied between the two.
            let front = tokio_rustls::TlsAcceptor::from(server_config().unwrap())
                .accept(proxy_front)
                .await
                .unwrap();
            let back = tokio_rustls::TlsConnector::from(client_config().unwrap())
                .connect(name(), proxy_back)
                .await
                .unwrap();
            let (mut fr, mut fw) = tokio::io::split(front);
            let (mut br, mut bw) = tokio::io::split(back);
            tokio::join!(
                async { tokio::io::copy(&mut fr, &mut bw).await.ok() },
                async { tokio::io::copy(&mut br, &mut fw).await.ok() }
            );
        });
        let mut c = tokio_rustls::TlsConnector::from(client_config().unwrap())
            .connect(name(), client_io)
            .await
            .unwrap();
        let e = bind(&mut c, &relay.id()).await.unwrap_err();
        assert!(is_intercepted(&e), "{}", e);
    }
}
