//! Regression tests for audit round 3 (ledger #857): five defects reproduced on `7a461b7` by two
//! independent auditors (Claude and Hermes), ported here and deduplicated. Each test failed on
//! that commit because of the defect it names; the two `*_holds` tests at the end pin claims
//! the auditors checked and found TRUE, so they stay true.
//!
//! Everything goes through a real [`Kernel`] with the keys bound as resources, so `key=<uri>`
//! resolves exactly as it does in production. No test shells out (the SEC1 fixtures were made
//! once with `openssl ec` from the same scalar as the PKCS8 fixture and are embedded below).

use async_trait::async_trait;
use base64::Engine as _;
use futures::executor::block_on;
use ikigai_core::{
    ArgRef, Capability, Endpoint, Error as CoreError, Exact, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Result as CoreResult, Verb,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p256::pkcs8::DecodePrivateKey;
use sha2::Digest;
use std::sync::Arc;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// The crate's own unit-test fixtures (src/tests.rs), verbatim.
const K1_PRIV: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIEIW/m80W4IrD82k3Mos0l4aeyfOkZMMZXqEYt6jpawc\n\
-----END PRIVATE KEY-----\n";
const K1_PUB: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAa9JuLzyLESJBF9LPZZ4RJk13iu5OhgKvLRQ3q0oQ4pE=\n\
-----END PUBLIC KEY-----\n";
const P256_PRIV: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBwcHBwcHBwcHBwcH\n\
BwcHBwcHBwcHBwcHBwcHBwcHBwehRANCAAQeGFMv1HVMAvMEHZx1zrM7g//YGsfO\n\
T+iCzLHJi8WJbqRsMRxOL/QN2Wo2U+bkVEXTLf5Ibs7XXHqQxqGIgcCj\n\
-----END PRIVATE KEY-----\n";
const P256_PUB: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHhhTL9R1TALzBB2cdc6zO4P/2BrH\n\
zk/ogsyxyYvFiW6kbDEcTi/0DdlqNlPm5FRF0y3+SG7O11x6kMahiIHAow==\n\
-----END PUBLIC KEY-----\n";

/// The SAME P-256 key as [`P256_PRIV`], in SEC1 (`openssl ec -in p256.pem`): what
/// `openssl ecparam -name prime256v1 -genkey -noout` writes.
const P256_SEC1_PEM: &str = "-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHoAoGCCqGSM49\n\
AwEHoUQDQgAEHhhTL9R1TALzBB2cdc6zO4P/2BrHzk/ogsyxyYvFiW6kbDEcTi/0\n\
DdlqNlPm5FRF0y3+SG7O11x6kMahiIHAow==\n\
-----END EC PRIVATE KEY-----\n";
/// The `EC PARAMETERS` block `openssl ecparam -genkey` writes BEFORE the key unless told
/// `-noout`: the named-curve OID for prime256v1.
const P256_EC_PARAMETERS: &str = "-----BEGIN EC PARAMETERS-----\n\
BggqhkjOPQMBBw==\n\
-----END EC PARAMETERS-----\n";
/// The `EC PARAMETERS` block for secp256k1 — a different curve.
const SECP256K1_EC_PARAMETERS: &str = "-----BEGIN EC PARAMETERS-----\n\
BgUrgQQACg==\n\
-----END EC PARAMETERS-----\n";
/// [`P256_SEC1_PEM`] as DER (`openssl ec -outform DER`).
const P256_SEC1_DER_B64: &str = "MHcCAQEEIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHoAoGCCqGSM49AwEHoUQDQgAEHhhTL9R1TALzBB2cdc6zO4P/2BrHzk/ogsyxyYvFiW6kbDEcTi/0DdlqNlPm5FRF0y3+SG7O11x6kMahiIHAow==";

// ---- fixtures -------------------------------------------------------------------------------

/// A key resource serving fixed bytes.
struct Key(Vec<u8>);

#[async_trait]
impl Endpoint for Key {
    async fn invoke(&self, _inv: &Invocation<'_>) -> CoreResult<Representation> {
        Ok(Representation::new(
            ReprType::new("application/octet-stream"),
            self.0.clone(),
        ))
    }
}

fn key(bytes: impl AsRef<[u8]>) -> Key {
    Key(bytes.as_ref().to_vec())
}

fn kernel_with(extra: &[(&str, Vec<u8>)]) -> Kernel {
    let mut space = ikigai_sign::space()
        .bind(Exact::new("urn:test:k1-priv"), key(K1_PRIV))
        .bind(Exact::new("urn:test:k1-pub"), key(K1_PUB))
        .bind(Exact::new("urn:test:p256-priv"), key(P256_PRIV))
        .bind(Exact::new("urn:test:p256-pub"), key(P256_PUB));
    for (iri, bytes) in extra {
        space = space.bind(Exact::new(*iri), key(bytes));
    }
    Kernel::new(Arc::new(space))
}

fn kernel() -> Kernel {
    kernel_with(&[])
}

fn try_sign(k: &Kernel, msg: &[u8], key_iri: &str) -> CoreResult<String> {
    let req = Request::new(Verb::Source, Iri::parse("urn:sign:sign").unwrap())
        .with_arg("in", ArgRef::Inline(msg.to_vec()))
        .with_arg("key", ArgRef::Inline(key_iri.as_bytes().to_vec()));
    block_on(k.issue(req, &Capability::scoped([ikigai_sign::CAP_SIGN])))
        .map(|r| String::from_utf8(r.bytes).unwrap())
}

fn sign(k: &Kernel, msg: &[u8], key_iri: &str) -> String {
    try_sign(k, msg, key_iri).expect("sign ok")
}

/// `Ok(verdict text)` or the typed error.
fn verify(k: &Kernel, msg: &[u8], graph: &str, key_iri: &str) -> CoreResult<String> {
    let req = Request::new(Verb::Source, Iri::parse("urn:sign:verify").unwrap())
        .with_arg("in", ArgRef::Inline(msg.to_vec()))
        .with_arg("sig", ArgRef::Inline(graph.as_bytes().to_vec()))
        .with_arg("key", ArgRef::Inline(key_iri.as_bytes().to_vec()));
    block_on(k.issue(req, &Capability::root())).map(|r| String::from_utf8(r.bytes).unwrap())
}

fn is_valid(r: &CoreResult<String>) -> bool {
    matches!(r, Ok(v) if v.starts_with("valid:"))
}

/// The literal of `sig:value` in an emitted graph.
fn sig_value(graph: &str) -> String {
    let line = graph
        .lines()
        .find(|l| l.contains(" sig:value "))
        .expect("sig:value line");
    let start = line.find('"').unwrap() + 1;
    let end = line.rfind('"').unwrap();
    line[start..end].to_string()
}

/// The subject IRI of the signature node in an emitted graph.
fn node_iri(graph: &str) -> String {
    let start = graph.find("<urn:sign:").unwrap() + 1;
    let rest = &graph[start..];
    rest[..rest.find('>').unwrap()].to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Re-address a graph onto a different `sig:value`, minting the node name exactly as
/// `urn:sign:sign` would — `urn:sign:sha256:{sha256(base64 value)}` — so the forgery is a
/// well-formed, properly content-addressed graph and nothing but the verifier can refuse it.
fn readdress(graph: &str, new_value_b64: &str) -> String {
    let node = format!(
        "urn:sign:sha256:{}",
        hex(&sha2::Sha256::digest(new_value_b64.as_bytes()))
    );
    graph
        .replace(&sig_value(graph), new_value_b64)
        .replace(&node_iri(graph), &node)
}

/// `(r, n − s)`: the other half of an ECDSA signature, made WITHOUT the private key.
fn ecdsa_twin(sig: &P256Signature) -> P256Signature {
    let (r, s) = sig.split_scalars();
    let neg_s: p256::Scalar = -*s;
    P256Signature::from_scalars(p256::FieldBytes::from(r), neg_s.to_bytes()).unwrap()
}

fn is_high_s(sig: &P256Signature) -> bool {
    sig.normalize_s().is_some()
}

// =============================================================================================
// Bug 1 (serious, both auditors): ES256 admitted TWO valid signatures per (message, key).
// =============================================================================================

/// The attack, as both auditors ran it: take an honest ES256 graph, replace `s` with `n − s`
/// (no key needed), re-address the node, and hand it to the OPEN verify endpoint. On `7a461b7`
/// it said `valid`, so one signed fact had two content-addressed names. The Ed25519 arm has
/// refused its equivalent since `verify_strict`; ES256 now refuses the high-S half.
#[test]
fn es256_high_s_twin_is_refused_with_a_reason() {
    let k = kernel();
    let msg = b"a booking decision";
    let graph = sign(&k, msg, "urn:test:p256-priv");
    assert!(is_valid(&verify(&k, msg, &graph, "urn:test:p256-pub")));

    let honest = P256Signature::from_slice(&B64.decode(sig_value(&graph)).unwrap()).unwrap();
    let twin = ecdsa_twin(&honest);
    let forged = readdress(&graph, &B64.encode(twin.to_bytes()));
    assert_ne!(node_iri(&forged), node_iri(&graph), "a second node name");

    let verdict = verify(&k, msg, &forged, "urn:test:p256-pub").expect("a verdict, not an error");
    assert!(
        verdict.starts_with("invalid:") && verdict.contains("high-S"),
        "the key-less (r, n-s) twin must be refused, and say why: {verdict}"
    );
}

/// The sign half. RFC 6979 fixes `k`, not which half of `s` comes out, so about half of all
/// raw P-256 signatures are high-S; before this fix `urn:sign:sign` emitted them as they came
/// and the high-S refusal above would have repudiated the module's own output. Find a message
/// whose RAW signature under the fixture key is high-S, then require the endpoint to emit the
/// low-S form of exactly that signature (same `r`, `s` normalized) — and that it verifies.
#[test]
fn es256_sign_emits_low_s_even_where_the_raw_signature_is_high() {
    let k = kernel();
    let raw_key = P256SigningKey::from_pkcs8_pem(P256_PRIV).unwrap();
    let (msg, raw) = (0u32..256)
        .map(|i| format!("message {i}").into_bytes())
        .map(|m| {
            let s: P256Signature = raw_key.sign(&m);
            (m, s)
        })
        .find(|(_, s)| is_high_s(s))
        .expect("about half of raw ECDSA signatures are high-S; 256 tries find one");

    let graph = sign(&k, &msg, "urn:test:p256-priv");
    let emitted = P256Signature::from_slice(&B64.decode(sig_value(&graph)).unwrap()).unwrap();
    assert!(!is_high_s(&emitted), "urn:sign:sign must emit low-S");
    assert_eq!(
        emitted,
        raw.normalize_s().unwrap(),
        "the emitted signature is the raw one, normalized"
    );
    assert!(is_valid(&verify(&k, &msg, &graph, "urn:test:p256-pub")));
}

// =============================================================================================
// Bugs 2 + 3 (minor, one root cause): the graph was read predicate by predicate across ALL
// subjects, so the verdict depended on triple order and the fields need not belong to the
// signature node at all.
// =============================================================================================

/// Two parties sign the same bytes and their graphs are concatenated (or `urn:rdf:union`ed).
/// On `7a461b7` one order said `valid` and the other erred, for the same set of triples. Now
/// both orders are refused the same way: a graph with two signatures is not ONE signature.
#[test]
fn two_signatures_in_one_graph_are_refused_in_either_order() {
    let k = kernel();
    let msg = b"co-signed contract";
    let ed = sign(&k, msg, "urn:test:k1-priv");
    let es = sign(&k, msg, "urn:test:p256-priv");

    for (label, graph) in [
        ("ed+es", format!("{ed}{es}")),
        ("es+ed", format!("{es}{ed}")),
    ] {
        for key_iri in ["urn:test:k1-pub", "urn:test:p256-pub"] {
            let r = verify(&k, msg, &graph, key_iri);
            assert!(
                matches!(&r, Err(CoreError::Endpoint(m)) if m.contains("2 `sig:Signature` nodes")),
                "{label} with {key_iri}: an ambiguous graph must be refused by name, got {r:?}"
            );
        }
    }
}

/// The smallest form: the `rdf:type` moved to an unrelated node, the fields left behind on an
/// untyped one. On `7a461b7` this said `valid` — the documented "literals of the single
/// `sig:Signature`" was not what the parser read.
#[test]
fn fields_are_read_from_the_signature_node_only() {
    let k = kernel();
    let msg = b"whose fields are these";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    let node = node_iri(&graph);
    let moved = graph.replace(
        &format!("<{node}> rdf:type sig:Signature ."),
        "<urn:example:unrelated> rdf:type sig:Signature .",
    );
    assert_ne!(moved, graph);
    let r = verify(&k, msg, &moved, "urn:test:k1-pub");
    assert!(
        matches!(&r, Err(CoreError::Endpoint(_))),
        "the sig:Signature node carries no fields, so there is nothing to verify: {r:?}"
    );
}

/// A complete, honest signature node plus ONE stray `sig:` field on another subject. Nothing
/// about the stray triple can change the verdict now, so it is refused rather than ignored: a
/// signature-graph whose `sig:` facts do not all describe its one signature is malformed.
#[test]
fn a_stray_sig_field_on_another_subject_is_refused() {
    let k = kernel();
    let msg = b"one signature, one stray";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    let stray = format!("{graph}<urn:example:elsewhere> sig:value \"AAAA\" .\n");
    let r = verify(&k, msg, &stray, "urn:test:k1-pub");
    assert!(
        matches!(&r, Err(CoreError::Endpoint(m)) if m.contains("urn:example:elsewhere")),
        "a sig: field off the signature node must be refused by name: {r:?}"
    );
}

/// Two values for one field ON the signature node: which one is "the" value is as arbitrary
/// as the cross-subject case, so it is refused the same way.
#[test]
fn a_repeated_field_on_the_signature_node_is_refused() {
    let k = kernel();
    let msg = b"two values";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    let node = node_iri(&graph);
    let doubled = format!("{graph}<{node}> sig:algorithm \"ES256\" .\n");
    let r = verify(&k, msg, &doubled, "urn:test:k1-pub");
    assert!(
        matches!(&r, Err(CoreError::Endpoint(m)) if m.contains("sig:algorithm")),
        "a repeated field must be refused by name: {r:?}"
    );
}

/// ★ By design, the node's NAME is still never read: the parse is per subject, but which
/// subject is decided by its `rdf:type`, not by its IRI. A signature node named anything at
/// all verifies — the old bare-hex form, the tagged form, or a name with no digest in it.
/// Unrelated triples about other subjects (a title for the signed document) are left alone.
#[test]
fn the_signature_node_is_found_by_type_and_its_name_is_never_read() {
    let k = kernel();
    let msg = b"named arbitrarily";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    let renamed = graph.replace(&node_iri(&graph), "urn:example:any-name-at-all");
    let annotated = format!(
        "{renamed}<urn:example:the-document> <http://purl.org/dc/terms/title> \"a title\" .\n"
    );
    let r = verify(&k, msg, &annotated, "urn:test:k1-pub");
    assert!(is_valid(&r), "the subject IRI is not an input: {r:?}");
}

// =============================================================================================
// Bug 4 (minor): the documented `openssl ecparam -name prime256v1 -genkey` key (SEC1) was
// refused; only PKCS8 parsed.
// =============================================================================================

/// The SEC1 forms `openssl ecparam -genkey` actually writes — with and without the leading
/// `EC PARAMETERS` block — and SEC1 DER, each signing BYTE-IDENTICALLY to the PKCS8 form of the
/// same scalar (deterministic signing makes that the strongest statement available: it is the
/// same key, not merely a key that loaded).
#[test]
fn sec1_p256_keys_sign_exactly_like_the_pkcs8_form() {
    let preamble = format!("{P256_EC_PARAMETERS}{P256_SEC1_PEM}");
    let der = B64.decode(P256_SEC1_DER_B64).unwrap();
    let k = kernel_with(&[
        ("urn:test:sec1", P256_SEC1_PEM.as_bytes().to_vec()),
        ("urn:test:sec1-preamble", preamble.into_bytes()),
        ("urn:test:sec1-der", der),
    ]);
    let msg = b"one key, three encodings";
    let pkcs8 = sign(&k, msg, "urn:test:p256-priv");
    for iri in [
        "urn:test:sec1",
        "urn:test:sec1-preamble",
        "urn:test:sec1-der",
    ] {
        let r = try_sign(&k, msg, iri);
        assert_eq!(r.as_ref().ok(), Some(&pkcs8), "{iri}: {r:?}");
    }
}

/// Accepting SEC1 must not mean accepting a key for some OTHER curve as if it were P-256. The
/// `EC PARAMETERS` preamble, and the curve named INSIDE the key, are both checked: p256's own
/// SEC1 reader does not check the latter (a 32-byte secp256k1 scalar with no public half would
/// load silently as a P-256 key and sign under a curve its owner never chose).
#[test]
fn a_sec1_key_naming_another_curve_is_refused() {
    // The preamble names secp256k1, the key itself P-256.
    let wrong_preamble = format!("{SECP256K1_EC_PARAMETERS}{P256_SEC1_PEM}");
    // SEC1 ECPrivateKey { version 1, privateKey 0x07×32, [0] secp256k1 } — no public key.
    let mut k1_der = vec![0x30, 0x2e, 0x02, 0x01, 0x01, 0x04, 0x20];
    k1_der.extend_from_slice(&[0x07; 32]);
    k1_der.extend_from_slice(&[0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]);
    let k = kernel_with(&[
        ("urn:test:wrong-preamble", wrong_preamble.into_bytes()),
        ("urn:test:k1-sec1", k1_der),
    ]);
    for iri in ["urn:test:wrong-preamble", "urn:test:k1-sec1"] {
        let r = try_sign(&k, b"x", iri);
        assert!(
            matches!(&r, Err(CoreError::Endpoint(m)) if m.contains("which is not P-256")),
            "{iri}: a non-P-256 SEC1 key must be refused, got {r:?}"
        );
    }
}

// =============================================================================================
// Bug 5 (minor): `resolve_key` promised http(s) is not a key transport; nothing checked.
// =============================================================================================

/// An `https:` key IRI is refused on BOTH endpoints, as a typed `InvalidArgument` on `key`,
/// before anything is resolved — even though the kernel here binds that IRI and would serve it.
/// `urn:` and `file:` stay accepted.
#[test]
fn a_key_iri_outside_urn_and_file_is_refused_before_resolution() {
    let k = kernel_with(&[
        ("https://keys.example/k1.pem", K1_PRIV.as_bytes().to_vec()),
        ("https://keys.example/k1.pub", K1_PUB.as_bytes().to_vec()),
        ("file:///keys/k1.pem", K1_PRIV.as_bytes().to_vec()),
        ("file:///keys/k1.pub", K1_PUB.as_bytes().to_vec()),
    ]);

    let signed = try_sign(&k, b"x", "https://keys.example/k1.pem");
    assert!(
        matches!(&signed, Err(CoreError::InvalidArgument { name, .. }) if name == "key"),
        "sign must refuse an https: key: {signed:?}"
    );

    let graph = sign(&k, b"x", "urn:test:k1-priv");
    let verified = verify(&k, b"x", &graph, "https://keys.example/k1.pub");
    assert!(
        matches!(&verified, Err(CoreError::InvalidArgument { name, .. }) if name == "key"),
        "verify must refuse an https: key: {verified:?}"
    );

    // The promise is an allowlist, and `file:` is on it.
    let via_file = sign(&k, b"x", "file:///keys/k1.pem");
    assert_eq!(via_file, graph, "a file: key signs like the urn: one");
    assert!(is_valid(&verify(
        &k,
        b"x",
        &via_file,
        "file:///keys/k1.pub"
    )));
}

// =============================================================================================
// Claims the auditors checked and found TRUE — pinned so they stay true.
// =============================================================================================

/// lib.rs says Ed25519 "S-scalar canonicity is enforced by `from_slice`": a non-canonical
/// `S + l` is not a second valid signature.
#[test]
fn ed25519_non_canonical_s_is_refused_claim_holds() {
    let k = kernel();
    let msg = b"canonical s";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    let mut sig = B64.decode(sig_value(&graph)).unwrap();
    // l = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for i in 0..32 {
        let t = sig[32 + i] as u16 + L[i] as u16 + carry;
        sig[32 + i] = t as u8;
        carry = t >> 8;
    }
    assert_eq!(carry, 0);
    let forged = readdress(&graph, &B64.encode(&sig));
    let r = verify(&k, msg, &forged, "urn:test:k1-pub");
    assert!(!is_valid(&r), "S + l must not verify: {r:?}");
}

/// The PEM sniff allows leading whitespace, so a key file with a blank first line loads.
#[test]
fn a_pem_key_with_leading_whitespace_loads_claim_holds() {
    let k = kernel_with(&[("urn:test:lead", format!("\n  \n{K1_PRIV}").into_bytes())]);
    assert_eq!(
        sign(&k, b"x", "urn:test:lead"),
        sign(&k, b"x", "urn:test:k1-priv")
    );
}
