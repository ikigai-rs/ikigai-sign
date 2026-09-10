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

// A P-256 (ES256) keypair — PKCS8 private + SPKI public, PEM — from a fixed scalar, so the
// ES256 tests are deterministic and RNG-free just like the Ed25519 ones. ES256 is the
// algorithm the Secure Enclave speaks; here it is a software key exercising the same dispatch.
const P256_PRIV: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBwcHBwcHBwcHBwcH\n\
BwcHBwcHBwcHBwcHBwcHBwcHBwehRANCAAQeGFMv1HVMAvMEHZx1zrM7g//YGsfO\n\
T+iCzLHJi8WJbqRsMRxOL/QN2Wo2U+bkVEXTLf5Ibs7XXHqQxqGIgcCj\n\
-----END PRIVATE KEY-----\n";
const P256_PUB: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHhhTL9R1TALzBB2cdc6zO4P/2BrH\n\
zk/ogsyxyYvFiW6kbDEcTi/0DdlqNlPm5FRF0y3+SG7O11x6kMahiIHAow==\n\
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

/// Like [`StaticKey`] but owns its bytes — for keys computed at test time (the weak-key vector
/// builds an SPKI-wrapped small-order public key), not embeddable as a `&'static str`.
struct OwnedKey(Vec<u8>);

#[async_trait]
impl Endpoint for OwnedKey {
    async fn invoke(&self, _inv: &Invocation<'_>) -> CoreResult<Representation> {
        Ok(Representation::new(
            ReprType::new("application/octet-stream"),
            self.0.clone(),
        ))
    }
}

/// A kernel over this crate's `space()` plus three bound key resources.
fn kernel() -> Kernel {
    let space = space()
        .bind(Exact::new("urn:test:k1-priv"), StaticKey(K1_PRIV))
        .bind(Exact::new("urn:test:k1-pub"), StaticKey(K1_PUB))
        .bind(Exact::new("urn:test:k2-pub"), StaticKey(K2_PUB))
        .bind(Exact::new("urn:test:p256-priv"), StaticKey(P256_PRIV))
        .bind(Exact::new("urn:test:p256-pub"), StaticKey(P256_PUB));
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

// ---- non-malleability: a weak-key forgery is rejected (verify vs verify_strict) ----------

/// Why verification is `verify_strict`, not the permissive `verify`. A signature IS this crate's
/// content-address (`urn:sign:{sha256(signature)}`), so a signature that verifies for a message
/// it was never honestly signed for would mint a bogus `urn:sign:<hash>` node for that fact.
/// Ed25519's *weak-key* malleability is exactly such a hole: a small-order public key admits a
/// forged signature that satisfies almost every message (here the identity point `A`, with the
/// trivial `s = 0`, `R = A`, so the verification point `[s]B − [k]A = 𝒪 = R` for ANY `k`). The
/// permissive `verify` accepts it; `verify_strict` rejects any small-order `A`/`R`
/// (`VerifyingKey::is_weak`). This test asserts both halves: (1) the plain `verify` ACCEPTS the
/// forgery — so it is a genuine malleability vector, not noise; (2) the OPEN `urn:sign:verify`
/// endpoint (now on `verify_strict`) REJECTS it end-to-end, key resolved through the kernel.
#[test]
fn weak_key_forgery_is_rejected_though_permissive_verify_accepts() {
    use ed25519_dalek::Verifier;

    let msg = b"a fact no one honestly signed";

    // The small-order public key: the Edwards identity point, compressed as `[1, 0, …, 0]`.
    let mut weak_pub = [0u8; 32];
    weak_pub[0] = 1;
    // The forgery: R = identity (`[1, 0, …, 0]`), s = 0. 64 bytes = R ‖ s.
    let mut forged_sig = [0u8; 64];
    forged_sig[0] = 1;

    // (1) The permissive `verify` accepts it — the malleability the content-address must not
    // admit. (If this ever stops holding, the vector is wrong and the test proves nothing.)
    let weak_vk = VerifyingKey::from_bytes(&weak_pub).unwrap();
    assert!(weak_vk.is_weak(), "the identity point is a small-order key");
    let sig = Signature::from_slice(&forged_sig).unwrap();
    assert!(
        weak_vk.verify(msg, &sig).is_ok(),
        "the weak-key forgery must satisfy the permissive equation (else it proves nothing)"
    );

    // (2) End-to-end through the OPEN endpoint, weak key resolved through the kernel. Take a real
    // sig-graph (for its shape + correct content hash of `msg`), then swap in the weak signer and
    // the forged value; the content-hash/signer pre-checks pass, so verification is reached.
    let spki = weak_key_spki(&weak_pub);
    let k = {
        let space = space()
            .bind(Exact::new("urn:test:k1-priv"), StaticKey(K1_PRIV))
            .bind(Exact::new("urn:test:weak-pub"), OwnedKey(spki));
        Kernel::new(Arc::new(space))
    };
    let graph = sign(&k, msg, "urn:test:k1-priv");
    let fields = parse_sig_graph(&graph).unwrap();
    let forged_graph = graph
        .replace(&fields.signer_b64.unwrap(), &B64.encode(weak_pub))
        .replace(&fields.value_b64, &B64.encode(forged_sig));
    assert_ne!(forged_graph, graph, "signer + value must have been swapped");

    let verdict = verify(&k, msg, &forged_graph, "urn:test:weak-pub");
    assert!(
        verdict.contains("does not verify"),
        "a weak-key forgery must fail strict verification, got: {verdict}"
    );
}

/// Wrap a 32-byte Ed25519 public key in its standard SPKI DER envelope, so it resolves through
/// the kernel exactly as a real `urn:*` key does (12-byte fixed Ed25519 SPKI prefix + the key).
fn weak_key_spki(pubkey: &[u8; 32]) -> Vec<u8> {
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    SPKI_PREFIX.iter().chain(pubkey).copied().collect()
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
    assert_eq!(
        fields.content_hash,
        format!("sha256:{}", content_hash_hex(msg))
    );
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
    // The declared capability — the kernel enforces it before dispatch, and the endpoint
    // re-checks it at entry (declared = enforced).
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
// ---- ES256 (P-256) round trip and cross-algorithm -----------------------------------------

#[test]
fn es256_round_trip_sign_then_verify_is_valid() {
    let k = kernel();
    let message = b"a booking decision, signed in the Enclave one day";
    let graph = sign(&k, message, "urn:test:p256-priv");
    // The graph declares ES256 and is verifiable with the matching public key.
    assert!(graph.contains(r#"sig:algorithm "ES256""#), "{graph}");
    let verdict = verify(&k, message, &graph, "urn:test:p256-pub");
    assert!(verdict.starts_with("valid:"), "{verdict}");
    assert!(verdict.contains("algorithm ES256"), "{verdict}");
}

#[test]
fn es256_signing_is_deterministic() {
    // RFC-6979 deterministic ECDSA — the same (message, key) signs byte-identically, so the
    // signature-graph stays content-addressable exactly like Ed25519.
    let k = kernel();
    let message = b"determinism keeps the graph content-addressable";
    assert_eq!(
        sign(&k, message, "urn:test:p256-priv"),
        sign(&k, message, "urn:test:p256-priv")
    );
}

#[test]
fn es256_tampered_content_is_invalid() {
    let k = kernel();
    let graph = sign(&k, b"pay 100", "urn:test:p256-priv");
    let verdict = verify(&k, b"pay 900", &graph, "urn:test:p256-pub");
    assert!(verdict.starts_with("invalid:"), "{verdict}");
}

#[test]
fn an_ed25519_key_cannot_verify_an_es256_signature() {
    // Dispatch is on the graph's algorithm: an ES256 graph handed an Ed25519 public key is a
    // clean error (the key won't parse as P-256), never a false "valid".
    let k = kernel();
    let graph = sign(&k, b"msg", "urn:test:p256-priv");
    let out = block_on(k.issue(
        verify_request(b"msg", &graph, "urn:test:k1-pub"),
        &Capability::root(),
    ));
    // A key that isn't a P-256 SPKI is a shape error surfaced as an endpoint error.
    assert!(
        out.is_err()
            || String::from_utf8(out.unwrap().bytes)
                .unwrap()
                .starts_with("invalid")
    );
}

#[test]
fn an_ed25519_signature_still_verifies_unchanged() {
    // The whole point of dispatch: adding ES256 did not disturb Ed25519.
    let k = kernel();
    let graph = sign(&k, b"unchanged", "urn:test:k1-priv");
    assert!(graph.contains(r#"sig:algorithm "Ed25519""#), "{graph}");
    let verdict = verify(&k, b"unchanged", &graph, "urn:test:k1-pub");
    assert!(verdict.contains("algorithm Ed25519"), "{verdict}");
}

// ---- the tagged digest: emission, back-compat, and refusal ------------------------------
//
// `sig:contentHash` names its algorithm — `sha256:<hex>`. Three properties are worth an
// executable statement, and only the first is about the new form: what is emitted, that what
// was emitted BEFORE still verifies, and that a tag this module does not implement is refused
// rather than quietly treated as SHA-256.

/// The 2026-08-07 public-record signature-graph, VERBATIM from
/// `ikigai-devtools/records/public-record-2026-08-07/ikigai-public-record.sig.ttl` — a real,
/// published, detached Ed25519 signature over a PDF, produced by `urn:sign:sign` before digests
/// were tagged. Its `sig:contentHash` is bare hex.
///
/// It is here as the shape of the compatibility promise: this exact literal must keep reading
/// as a SHA-256 digest. The signed PDF itself is NOT vendored (it lives in a private repo and
/// copying it here would republish it), so this fixture proves the parse and the digest
/// interpretation on the genuine bytes of the graph, and
/// [`an_untagged_pre_tag_graph_still_verifies`] proves the end-to-end verification on the same
/// lexical form with a key this crate owns.
const PUBLIC_RECORD_2026_08_07: &str = concat!(
    "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n",
    "@prefix sig: <https://ikigai-rs.dev/ns/sign#> .\n",
    "<urn:sign:7b6c919ef0728338c8507b8238c9acc16d65166290d66731af62e157d370ff0b> rdf:type sig:Signature .\n",
    "<urn:sign:7b6c919ef0728338c8507b8238c9acc16d65166290d66731af62e157d370ff0b> sig:algorithm \"Ed25519\" .\n",
    "<urn:sign:7b6c919ef0728338c8507b8238c9acc16d65166290d66731af62e157d370ff0b> sig:signer \"KWvlAFPnW2d+4J/VM9A8ej9Qi0gKB0UcguzVyjqsBy0=\" .\n",
    "<urn:sign:7b6c919ef0728338c8507b8238c9acc16d65166290d66731af62e157d370ff0b> sig:value \"ssVA1iBRyim5Zv6rEGLLWp7OnEj7ftMraRterkJI0b6zEoIdpET1OyoIAK35pLB24erp+dMH93CIktu6OuK6DQ==\" .\n",
    "<urn:sign:7b6c919ef0728338c8507b8238c9acc16d65166290d66731af62e157d370ff0b> sig:contentHash \"ec2a37cef8f7a15ef2b635adc6e82a989a33156100e63e70fa6dd0339f7de58e\" .\n",
);

/// The public key that record was signed under (`public-record.pub`), so the historical graph
/// can be pushed through the real endpoint and not just the parser.
const PUBLIC_RECORD_PUB: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAKWvlAFPnW2d+4J/VM9A8ej9Qi0gKB0UcguzVyjqsBy0=\n\
-----END PUBLIC KEY-----\n";

/// The digest of the PDF that record signs, as the record wrote it: bare hex, no tag.
const PUBLIC_RECORD_HASH: &str = "ec2a37cef8f7a15ef2b635adc6e82a989a33156100e63e70fa6dd0339f7de58e";

#[test]
fn emitted_content_hash_is_tagged_sha256() {
    let k = kernel();
    let msg = b"tag the digest";
    let graph = sign(&k, msg, "urn:test:k1-priv");

    let fields = parse_sig_graph(&graph).expect("the sig-graph parses");
    assert_eq!(
        fields.content_hash,
        format!("sha256:{}", content_hash_hex(msg)),
        "sig:contentHash must name its algorithm"
    );
    assert!(
        graph.contains(r#"sig:contentHash "sha256:"#),
        "the tag must survive serialization, got: {graph}"
    );
    // And a tagged graph still verifies — the tag is not a separate dialect.
    let verdict = verify(&k, msg, &graph, "urn:test:k1-pub");
    assert!(verdict.starts_with("valid:"), "{verdict}");
}

#[test]
fn es256_content_hash_is_tagged_too() {
    let k = kernel();
    let msg = b"tagged under es256";
    let graph = sign(&k, msg, "urn:test:p256-priv");
    assert!(
        graph.contains(&format!(
            r#"sig:contentHash "sha256:{}""#,
            content_hash_hex(msg)
        )),
        "the digest tag is a property of the DIGEST, not of the signature algorithm: {graph}"
    );
    let verdict = verify(&k, msg, &graph, "urn:test:p256-pub");
    assert!(verdict.starts_with("valid:"), "{verdict}");
}

/// ★ The back-compat guarantee, end-to-end: a signature-graph in the PRE-TAG lexical form —
/// `sig:contentHash` as bare hex, exactly as the 2026-08-07 public record carries it — still
/// verifies through the real endpoint. A change that broke this would not be a formatting
/// change; it would repudiate every record already signed.
#[test]
fn an_untagged_pre_tag_graph_still_verifies() {
    let k = kernel();
    let msg = b"signed before digests were tagged";
    let graph = sign(&k, msg, "urn:test:k1-priv");

    // Strip the tag from the DIGEST LITERAL, reproducing what this module used to emit there.
    // (The node IRI carries a `sha256:` of its own since 0.2.1 — a different tag on a
    // different digest, stripped by `strip_node_tag` in the old-form test below.)
    let legacy = graph.replace(
        &format!(r#"sig:contentHash "sha256:{}""#, content_hash_hex(msg)),
        &format!(r#"sig:contentHash "{}""#, content_hash_hex(msg)),
    );
    assert_ne!(legacy, graph, "the tag must have been stripped");
    assert!(
        legacy.contains(&format!(r#"sig:contentHash "{}""#, content_hash_hex(msg))),
        "the legacy digest carries no tag: {legacy}"
    );

    let verdict = verify(&k, msg, &legacy, "urn:test:k1-pub");
    assert!(
        verdict.starts_with("valid:"),
        "an untagged (pre-0.2) signature-graph must still verify, got: {verdict}"
    );
}

/// The genuine 2026-08-07 artifact, through the parser and the endpoint. Its untagged digest
/// must be READ as SHA-256 — the proof is the reason line: the endpoint reaches the hash
/// COMPARISON (and names the record's own digest as what was signed) instead of refusing the
/// literal as an unknown algorithm. The signed PDF is not vendored here, so this is verified
/// against different bytes and the expected answer is a mismatch, not a valid verdict.
#[test]
fn the_2026_08_07_public_record_still_reads_as_sha256() {
    let fields = parse_sig_graph(PUBLIC_RECORD_2026_08_07).expect("the historical graph parses");
    assert_eq!(fields.algorithm, "Ed25519");
    assert_eq!(fields.content_hash, PUBLIC_RECORD_HASH, "bare hex, no tag");
    assert_eq!(
        content_hash_sha256_hex(&fields.content_hash),
        Ok(PUBLIC_RECORD_HASH),
        "an untagged digest is a SHA-256 digest"
    );

    let space = space().bind(
        Exact::new("urn:test:public-record-pub"),
        StaticKey(PUBLIC_RECORD_PUB),
    );
    let k = Kernel::new(Arc::new(space));
    let verdict = verify(
        &k,
        b"not the public-record PDF",
        PUBLIC_RECORD_2026_08_07,
        "urn:test:public-record-pub",
    );
    assert!(
        verdict.contains(&format!(
            "content hash mismatch (signed {PUBLIC_RECORD_HASH}"
        )),
        "the historical untagged digest must reach the comparison, not be refused: {verdict}"
    );
}

/// The tag must not become a way to SKIP the comparison: a correctly tagged digest whose hex
/// is wrong still fails.
#[test]
fn a_tagged_hash_with_wrong_hex_still_fails() {
    let k = kernel();
    let msg = b"honest bytes";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    let real = content_hash_hex(msg);
    // Corrupt one hex digit, keeping the tag intact.
    let corrupted: String = {
        let mut c = real.clone();
        let first = if c.starts_with('a') { 'b' } else { 'a' };
        c.replace_range(0..1, &first.to_string());
        c
    };
    let tampered = graph.replace(&format!("sha256:{real}"), &format!("sha256:{corrupted}"));
    assert_ne!(tampered, graph, "the digest must have been corrupted");

    let verdict = verify(&k, msg, &tampered, "urn:test:k1-pub");
    assert!(
        verdict.contains("content hash mismatch"),
        "a tagged-but-wrong digest must still fail, got: {verdict}"
    );
}

/// ★ An unknown tag is REFUSED, not assumed. The hex here is CORRECT — a verifier that merely
/// stripped whatever tag it found would say `valid`, and the tag would be decoration. The
/// signature itself is over the bytes and does check out, so nothing but this refusal stands
/// between a `blake3:` digest and a confident `valid` on a comparison that never happened.
#[test]
fn an_unknown_hash_tag_is_refused_not_assumed() {
    let k = kernel();
    let msg = b"hashed with something else";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    // Only the DIGEST is mislabelled — the node IRI's own tag is left alone, so this test
    // says something about `sig:contentHash` and nothing about the identifier.
    let mislabelled = graph.replace(
        &format!(r#"sig:contentHash "sha256:{}""#, content_hash_hex(msg)),
        &format!(r#"sig:contentHash "blake3:{}""#, content_hash_hex(msg)),
    );
    assert!(
        mislabelled.contains(r#"sig:contentHash "blake3:"#),
        "{mislabelled}"
    );

    let verdict = verify(&k, msg, &mislabelled, "urn:test:k1-pub");
    assert!(
        verdict.starts_with("invalid:"),
        "an unrecognised digest algorithm must not verify, got: {verdict}"
    );
    assert!(
        verdict.contains("unsupported content-hash algorithm `blake3`"),
        "and it must say WHY — a clear refusal, not a silent mismatch: {verdict}"
    );
}

/// The digest-literal parser, stated directly: the three cases and their answers.
#[test]
fn content_hash_literal_parsing_is_total() {
    assert_eq!(content_hash_sha256_hex("sha256:abc"), Ok("abc"));
    assert_eq!(content_hash_sha256_hex("abc"), Ok("abc"), "pre-0.2 form");
    assert_eq!(content_hash_sha256_hex("blake3:abc"), Err("blake3"));
    assert_eq!(content_hash_sha256_hex(":abc"), Err(""), "empty tag");
    // Case matters: exactly one spelling is emitted and exactly one is accepted.
    assert_eq!(content_hash_sha256_hex("SHA256:abc"), Err("SHA256"));
}

// ---- the tagged identifier: derivation, both algorithms, and the old form -----------------
//
// The signature node's IRI is `urn:sign:sha256:<hex>` — the digest that addresses it names
// itself, exactly as `sig:contentHash` does. Three things are worth stating executably: WHAT
// the name is derived from (unchanged, and load-bearing), that both algorithms mint the tagged
// form, and that a graph carrying the OLD bare-hex name still verifies. The last is the
// guarantee: an identifier that changed shape would be a migration if anything read it, and
// nothing does.

/// The subject IRI of the single `sig:Signature` in an emitted graph.
fn node_iri(graph: &str) -> &str {
    let start = graph
        .find("<urn:sign:")
        .expect("the graph names a signature node")
        + 1;
    let rest = &graph[start..];
    &rest[..rest.find('>').expect("the IRI is closed")]
}

/// ★ The property the tag must NOT disturb: the node is content-addressed ON THE SIGNATURE.
/// `sha256(base64 sig:value)` is what names it — before the tag and after — because that is
/// what makes the name unforgeable: verification admits exactly one valid signature per
/// (message, key) (`verify_strict`; see
/// [`weak_key_forgery_is_rejected_though_permissive_verify_accepts`]), so exactly one node IRI
/// can be minted for a signed fact. Address it on anything weaker — the message, the signer —
/// and a forgery mints a name that says a thing that was never signed.
///
/// Nothing pinned this derivation before 0.2.1 — the previous assertion was only that the IRI
/// starts `urn:sign:` — and it moved once unnoticed because of that: 0.1.0 hashed the RAW
/// signature bytes, 0.2.0's crypto-agility refactor hashed the base64 TEXT of them instead
/// (the 2026-08-07 public record is named under the older preimage, `7b6c919e…`, where this
/// code would mint `fbb203be…`). Both name the same signature, and no reader compares the two,
/// so nothing broke; the point of this test is that the next move cannot be silent.
#[test]
fn the_node_iri_is_tagged_and_still_addresses_the_signature() {
    let k = kernel();
    let msg = b"name the digest that names the node";
    let graph = sign(&k, msg, "urn:test:k1-priv");
    let fields = parse_sig_graph(&graph).expect("the sig-graph parses");

    let node = node_iri(&graph);
    let expected_hex = to_hex(&Sha256::digest(fields.value_b64.as_bytes()));
    assert_eq!(
        node,
        format!("urn:sign:{HASH_ALG_SHA256}:{expected_hex}"),
        "the node names its digest algorithm AND is still sha256(base64 signature)"
    );

    // Said the other way round, so a future edit to either half fails loudly: the tag is a
    // prefix on the SAME hex the untagged form carried.
    assert!(node.starts_with("urn:sign:sha256:"), "{node}");
    assert_eq!(
        node.trim_start_matches("urn:sign:sha256:"),
        expected_hex,
        "the tag was added to the name, not to what the name is derived from"
    );
}

/// The tagged name does not collide with the module's own `Exact` bindings, and is positively
/// distinguishable from them rather than merely accidentally distinct — everything under
/// `urn:sign:sha256:` is a signature node, `urn:sign:sign` / `urn:sign:verify` are endpoints.
#[test]
fn a_signature_node_never_collides_with_the_endpoint_iris() {
    let k = kernel();
    let graph = sign(&k, b"neighbourhood check", "urn:test:k1-priv");
    let node = node_iri(&graph);
    assert_ne!(node, "urn:sign:sign");
    assert_ne!(node, "urn:sign:verify");
    Iri::parse(node).expect("the minted node is a well-formed IRI");
}

/// Both algorithms mint the tagged form — the digest that addresses the node is SHA-256
/// whichever algorithm signed, so the tag is a property of the addressing, not of the
/// signature algorithm (the same split as `sig:contentHash`).
#[test]
fn es256_mints_the_tagged_node_too() {
    let k = kernel();
    let msg = b"tagged identifier under es256";
    let graph = sign(&k, msg, "urn:test:p256-priv");
    let fields = parse_sig_graph(&graph).expect("the sig-graph parses");
    assert_eq!(fields.algorithm, "ES256");
    assert_eq!(
        node_iri(&graph),
        format!(
            "urn:sign:{HASH_ALG_SHA256}:{}",
            to_hex(&Sha256::digest(fields.value_b64.as_bytes()))
        )
    );
}

/// ★ The back-compat guarantee for the NAME, end-to-end through the kernel: a graph whose
/// subject is the old bare-hex `urn:sign:<hex>` still verifies. It holds because
/// [`parse_sig_graph`] never reads the subject — this test is what makes that an explicit
/// promise rather than an implication of the current implementation, so a future parser that
/// started matching on the node would fail here instead of silently repudiating every
/// signature-graph written before 0.2.1. (The genuine 2026-08-07 public record carries exactly
/// this form and reaches the endpoint too — see
/// [`the_2026_08_07_public_record_still_reads_as_sha256`].)
#[test]
fn an_old_form_bare_hex_node_still_verifies() {
    let k = kernel();
    let msg = b"named before identifiers were tagged";
    let graph = sign(&k, msg, "urn:test:k1-priv");

    // Reproduce the pre-0.2.1 name: strip the tag from the SUBJECT only.
    let old_form = graph.replace("<urn:sign:sha256:", "<urn:sign:");
    assert_ne!(old_form, graph, "the node tag must have been stripped");
    assert!(
        node_iri(&old_form).starts_with("urn:sign:")
            && !node_iri(&old_form).starts_with("urn:sign:sha256:"),
        "the old form is a bare hex name: {}",
        node_iri(&old_form)
    );
    // The digest literal is untouched — this test is about the NAME alone.
    assert!(old_form.contains(&format!(
        r#"sig:contentHash "sha256:{}""#,
        content_hash_hex(msg)
    )));

    let verdict = verify(&k, msg, &old_form, "urn:test:k1-pub");
    assert!(
        verdict.starts_with("valid:"),
        "a pre-0.2.1 bare-hex node must still verify, got: {verdict}"
    );
}

// ---- the wire shapes of sig:signer and sig:value, per algorithm ---------------------------

/// The two literals a consumer DECODES, pinned per algorithm. Their doc comments drifted once
/// (2026-08-23: "32-byte Ed25519 public key" / "64-byte Ed25519 signature") because the tests
/// asserted round-trip validity and never the field shape. The shapes: `sig:signer` is in the
/// ALGORITHM'S encoding — 32 raw bytes for Ed25519, a 91-byte SPKI DER document for ES256 —
/// and `sig:value` is 64 bytes for both. Neither length identifies the algorithm; read
/// `sig:algorithm` first (README, "The signature is a graph"). A change here is a wire-format
/// change for every consumer, `ikigai-log`'s seals included.
#[test]
fn signer_and_value_shapes_are_pinned_per_algorithm() {
    let k = kernel();
    let decode = |b64: &str| B64.decode(b64.as_bytes()).expect("valid base64");

    let ed = parse_sig_graph(&sign(&k, b"shape", "urn:test:k1-priv")).unwrap();
    let ed_signer = decode(ed.signer_b64.as_deref().unwrap());
    assert_eq!(
        ed_signer.len(),
        32,
        "Ed25519 sig:signer is the raw public key"
    );
    assert_eq!(decode(&ed.value_b64).len(), 64, "Ed25519 sig:value is R‖S");
    assert!(
        parse_ed25519_public(&ed_signer).is_err(),
        "the raw key is NOT an SPKI document — the two encodings are not interchangeable"
    );

    let es = parse_sig_graph(&sign(&k, b"shape", "urn:test:p256-priv")).unwrap();
    let es_signer = decode(es.signer_b64.as_deref().unwrap());
    // SPKI DER: a SEQUENCE (0x30) of 89 bytes — the AlgorithmIdentifier plus the 65-byte
    // uncompressed point — 91 bytes in all, and it re-parses as the public key.
    assert_eq!(
        es_signer.len(),
        91,
        "ES256 sig:signer is an SPKI DER document"
    );
    assert_eq!(&es_signer[..2], &[0x30, 0x59]);
    assert!(parse_p256_public(&es_signer).is_ok());
    assert_eq!(
        decode(&es.value_b64).len(),
        64,
        "ES256 sig:value is fixed-width r‖s, not DER"
    );
}
