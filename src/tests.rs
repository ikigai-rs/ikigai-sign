//! Tests for `ikigai-sign`: the pure sign/verify core, the sig-graph codec, and the two
//! endpoints end-to-end through a real [`Kernel`] — with the key bound as a kernel resource, so
//! `key=<uri>` genuinely resolves through the kernel (as it will in production).

use super::*;
use futures::executor::block_on;
use ikigai_core::{ArgRef, Capability, Kernel, Resolution, Scope, Space};
use std::sync::Arc;

// Two real Ed25519 keypairs, generated with `openssl genpkey -algorithm ed25519` (PKCS8
// private + SPKI public, PEM). k2 is the "wrong key" for the tamper tests. Embedding fixed
// keys keeps the tests deterministic and needs no RNG in this (keygen-free) crate.
const K1_PRIV: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIEIW/m80W4IrD82k3Mos0l4aeyfOkZMMZXqEYt6jpawc\n\
-----END PRIVATE KEY-----\n";
const K1_PUB: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAa9JuLzyLESJBF9LPZZ4RJk13iu5OhgKvLRQ3q0oQ4pE=\n\
-----END PUBLIC KEY-----\n";
const K2_PUB: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAi+9rQO2fsE5jSht+Wi2itGXQQx/or4ygbZ3CJqIC8wU=\n\
-----END PUBLIC KEY-----\n";

// ---- a static-bytes key endpoint, so a key resolves THROUGH the kernel -------------------

/// An endpoint that serves fixed bytes — stands in for a `urn:file:*` / `urn:secret:*` key
/// resource, so a `key=<uri>` argument resolves through the kernel exactly as in production.
struct StaticKey(&'static str);

#[async_trait]
impl Endpoint for StaticKey {
    async fn invoke(&self, _inv: &Invocation<'_>) -> CoreResult<Representation> {
        Ok(Representation::new(
            ReprType::new("application/x-pem-file"),
            self.0.as_bytes().to_vec(),
        ))
    }
}

/// A kernel over this crate's `space()` plus three bound key resources.
fn kernel() -> Kernel {
    let space = space()
        .bind(Exact::new("urn:test:k1-priv"), StaticKey(K1_PRIV))
        .bind(Exact::new("urn:test:k1-pub"), StaticKey(K1_PUB))
        .bind(Exact::new("urn:test:k2-pub"), StaticKey(K2_PUB));
    Kernel::new(Arc::new(space))
}

fn sign_request(message: &[u8], key_uri: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:sign:sign").unwrap())
        .with_arg("in", ArgRef::Inline(message.to_vec()))
        .with_arg("key", ArgRef::Inline(key_uri.as_bytes().to_vec()))
}

fn verify_request(message: &[u8], sig_graph: &str, key_uri: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:sign:verify").unwrap())
        .with_arg("in", ArgRef::Inline(message.to_vec()))
        .with_arg("sig", ArgRef::Inline(sig_graph.as_bytes().to_vec()))
        .with_arg("key", ArgRef::Inline(key_uri.as_bytes().to_vec()))
}

/// Sign with the `urn:cap:sign` grant, returning the signature-graph Turtle.
fn sign(k: &Kernel, message: &[u8], key_uri: &str) -> String {
    let cap = Capability::scoped([CAP_SIGN]);
    let repr = block_on(k.issue(sign_request(message, key_uri), &cap)).expect("sign ok");
    String::from_utf8(repr.bytes).unwrap()
}

/// Verify (open — no cap needed), returning the `text/plain` verdict.
fn verify(k: &Kernel, message: &[u8], sig_graph: &str, key_uri: &str) -> String {
    let repr = block_on(k.issue(
        verify_request(message, sig_graph, key_uri),
        &Capability::root(),
    ))
    .expect("verify ran (a bad signature is still Ok)");
    String::from_utf8(repr.bytes).unwrap()
}

// ---- round trip -------------------------------------------------------------------------

#[test]
fn round_trip_sign_then_verify_is_valid() {
    let k = kernel();
    let msg = b"the quick brown fox jumps over the lazy dog";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    let verdict = verify(&k, msg, &graph, "urn:test:k1-pub");
    assert!(
        verdict.starts_with("valid:"),
        "round-trip must verify, got: {verdict}"
    );
}

// ---- tamper detection -------------------------------------------------------------------

#[test]
fn wrong_public_key_is_invalid() {
    let k = kernel();
    let msg = b"authentic message";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    // Same message + genuine signature, but verified against a DIFFERENT public key.
    let verdict = verify(&k, msg, &graph, "urn:test:k2-pub");
    assert!(
        verdict.starts_with("invalid:"),
        "a mismatched pubkey must be invalid, got: {verdict}"
    );
}

#[test]
fn tampered_content_is_invalid_by_hash_mismatch() {
    let k = kernel();
    let msg = b"send $10 to alice";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    // Verify a DIFFERENT message against the signature of the original.
    let verdict = verify(&k, b"send $1000000 to mallory", &graph, "urn:test:k1-pub");
    assert!(
        verdict.contains("content hash mismatch"),
        "tampered content must fail the hash pre-check, got: {verdict}"
    );
}

#[test]
fn tampered_signature_value_is_invalid() {
    let k = kernel();
    let msg = b"authentic message";
    let graph = sign(&k, msg, "urn:test:k1-priv");

    // Flip the base64 sig:value to a different (but still 64-byte) signature: replace it with
    // an all-A base64 block of the right length. The content hash still matches, so this
    // exercises the Ed25519 check itself, not the hash pre-check.
    let fields = parse_sig_graph(&graph).unwrap();
    let bogus = B64.encode([0u8; 64]);
    let tampered = graph.replace(&fields.value_b64, &bogus);
    assert_ne!(tampered, graph, "the sig:value must have been replaced");

    let verdict = verify(&k, msg, &tampered, "urn:test:k1-pub");
    assert!(
        verdict.contains("does not verify"),
        "a tampered signature must fail the Ed25519 check, got: {verdict}"
    );
}

// ---- the signature-graph is valid RDF with the expected triples --------------------------

#[test]
fn signature_graph_parses_as_rdf_with_expected_triples() {
    let k = kernel();
    let msg = b"graph shape";
    let graph = sign(&k, msg, "urn:test:k1-priv");

    // It re-parses as RDF and carries the four sig:* facts + the rdf:type.
    let fields = parse_sig_graph(&graph).expect("the sig-graph parses as RDF");
    assert_eq!(fields.algorithm, "Ed25519");
    assert_eq!(fields.content_hash, content_hash_hex(msg));
    assert!(fields.signer_b64.is_some(), "sig:signer is present");
    // sig:value decodes to a 64-byte Ed25519 signature.
    let sig_bytes = B64.decode(fields.value_b64.as_bytes()).unwrap();
    assert_eq!(sig_bytes.len(), 64);

    // The raw Turtle binds the sig: prefix and uses it for the class + every predicate.
    assert!(
        graph.contains(&format!("@prefix sig: <{SIG_NS}> .")),
        "graph binds the sig: prefix"
    );
    for needle in [
        "rdf:type sig:Signature",
        "sig:algorithm",
        "sig:signer",
        "sig:value",
        "sig:contentHash",
    ] {
        assert!(graph.contains(needle), "graph must use `{needle}`");
    }
    // Skolemized: a stable content-addressed node IRI, no blank nodes.
    assert!(graph.contains("<urn:sign:"), "node IRI is skolemized");
    assert!(!graph.contains("_:"), "no blank nodes");
}

// ---- determinism ------------------------------------------------------------------------

#[test]
fn signing_is_deterministic_byte_identical() {
    let k = kernel();
    let msg = b"deterministic please";
    let a = sign(&k, msg, "urn:test:k1-priv");
    let b = sign(&k, msg, "urn:test:k1-priv");
    assert_eq!(
        a, b,
        "same bytes + key must yield a byte-identical sig-graph"
    );
}

// ---- capability enforcement -------------------------------------------------------------

#[test]
fn sign_without_cap_is_typed_denied() {
    let k = kernel();
    // A capability that grants something else — but NOT urn:cap:sign.
    let cap = Capability::scoped(["urn:cap:other"]);
    let err = block_on(k.issue(sign_request(b"x", "urn:test:k1-priv"), &cap)).unwrap_err();
    assert!(
        matches!(err, CoreError::Denied(_)),
        "signing without urn:cap:sign must be a typed Denied, got: {err:?}"
    );
    assert!(!err.is_transient(), "Denied is permanent");
}

#[test]
fn verify_needs_no_capability() {
    let k = kernel();
    let msg = b"open verification";
    // Sign needs the grant...
    let graph = sign(&k, msg, "urn:test:k1-priv");
    // ...but verify runs under an empty (scoped-to-nothing) capability.
    let repr = block_on(k.issue(
        verify_request(msg, &graph, "urn:test:k1-pub"),
        &Capability::scoped(Vec::<String>::new()),
    ))
    .expect("verify needs no capability");
    let verdict = String::from_utf8(repr.bytes).unwrap();
    assert!(verdict.starts_with("valid:"), "got: {verdict}");
}

// ---- malformed inputs never panic, always a clean error ---------------------------------

#[test]
fn malformed_signature_graph_is_a_clean_error() {
    let k = kernel();
    let err = block_on(k.issue(
        verify_request(b"x", "this is not turtle {{{", "urn:test:k1-pub"),
        &Capability::root(),
    ))
    .unwrap_err();
    assert!(matches!(err, CoreError::Endpoint(_)), "got: {err:?}");
}

#[test]
fn signature_graph_missing_fields_is_a_clean_error() {
    let k = kernel();
    // Well-formed Turtle, a sig:Signature, but no sig:value/algorithm/contentHash.
    let bare = format!("@prefix sig: <{SIG_NS}> .\n<urn:sign:x> a sig:Signature .\n");
    let err = block_on(k.issue(
        verify_request(b"x", &bare, "urn:test:k1-pub"),
        &Capability::root(),
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CoreError::Endpoint(m) if m.contains("missing")),
        "got: {err:?}"
    );
}

#[test]
fn malformed_private_key_is_a_clean_error() {
    let k = {
        let space = space().bind(Exact::new("urn:test:junk"), StaticKey("not a key at all"));
        Kernel::new(Arc::new(space))
    };
    let err = block_on(k.issue(
        sign_request(b"x", "urn:test:junk"),
        &Capability::scoped([CAP_SIGN]),
    ))
    .unwrap_err();
    assert!(matches!(err, CoreError::Endpoint(_)), "got: {err:?}");
}

#[test]
fn malformed_public_key_is_a_clean_error() {
    let k = {
        let space = space().bind(Exact::new("urn:test:junk"), StaticKey("not a key"));
        Kernel::new(Arc::new(space))
    };
    // A real signature-graph, but a junk public key resource → clean error, no panic.
    let good = kernel();
    let graph = sign(&good, b"x", "urn:test:k1-priv");
    let err = block_on(k.issue(
        verify_request(b"x", &graph, "urn:test:junk"),
        &Capability::root(),
    ))
    .unwrap_err();
    assert!(matches!(err, CoreError::Endpoint(_)), "got: {err:?}");
}

// ---- piped content: sign accepts the bytes via `content`, verify the graph via `content` --

#[test]
fn sign_reads_bytes_from_piped_content() {
    let k = kernel();
    let msg = b"piped in";
    let req = Request::new(Verb::Source, Iri::parse("urn:sign:sign").unwrap())
        .with_arg("content", ArgRef::Inline(msg.to_vec()))
        .with_arg("key", ArgRef::Inline(b"urn:test:k1-priv".to_vec()));
    let repr = block_on(k.issue(req, &Capability::scoped([CAP_SIGN]))).expect("sign ok");
    let graph = String::from_utf8(repr.bytes).unwrap();
    // And it verifies (using `content` for the sig-graph on the verify side too).
    let vreq = Request::new(Verb::Source, Iri::parse("urn:sign:verify").unwrap())
        .with_arg("in", ArgRef::Inline(msg.to_vec()))
        .with_arg("content", ArgRef::Inline(graph.into_bytes()))
        .with_arg("key", ArgRef::Inline(b"urn:test:k1-pub".to_vec()));
    let verdict =
        String::from_utf8(block_on(k.issue(vreq, &Capability::root())).unwrap().bytes).unwrap();
    assert!(verdict.starts_with("valid:"), "got: {verdict}");
}

// ---- describe / manifold: the declared contract --------------------------------------------

#[test]
fn sign_describe_declares_cap_and_args() {
    let request = Request::new(Verb::Meta, Iri::parse("urn:sign:sign").unwrap());
    let Resolution::Hit(resolved) = space().resolve(&request, &Scope::empty()) else {
        panic!("urn:sign:sign resolves");
    };
    let d = resolved.endpoint.describe();
    assert!(d.verbs.contains(&Verb::Source));
    // The declared capability the endpoint enforces (declared == enforced).
    assert!(
        d.requires.iter().any(|c| c == CAP_SIGN),
        "sign must declare {CAP_SIGN}; got {:?}",
        d.requires
    );
    let arg_names: Vec<&str> = d.inputs.iter().map(|a| a.name.as_str()).collect();
    for expected in ["in", "key"] {
        assert!(arg_names.contains(&expected), "sign declares `{expected}`");
    }
}

#[test]
fn verify_describe_is_open_and_declares_args() {
    let request = Request::new(Verb::Meta, Iri::parse("urn:sign:verify").unwrap());
    let Resolution::Hit(resolved) = space().resolve(&request, &Scope::empty()) else {
        panic!("urn:sign:verify resolves");
    };
    let d = resolved.endpoint.describe();
    assert!(d.verbs.contains(&Verb::Source));
    assert!(d.requires.is_empty(), "verify is open (no required cap)");
    let arg_names: Vec<&str> = d.inputs.iter().map(|a| a.name.as_str()).collect();
    for expected in ["in", "sig", "key"] {
        assert!(
            arg_names.contains(&expected),
            "verify declares `{expected}`"
        );
    }
}
