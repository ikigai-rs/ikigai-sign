//! The module recipe as one test: `ikigai-conformance` walks the two endpoints
//! [`ikigai_sign::space`] binds and reports every violation at once.
//!
//! ## The keystore is a fixture — and it decides what is cacheable
//!
//! Neither endpoint is pure. `sign` reads the private key THROUGH the kernel
//! (`key=<uri>`, resolved with `inv.issue`) and `verify` reads the public key the
//! same way, and the kernel folds each sub-resolution's expiry and golden threads
//! into the result. So a signature is exactly as cacheable as the key it was made
//! with, and no more:
//!
//! - a key served UNDER A THREAD (an `ikigai-fs` cacheable mount names
//!   `urn:file:<path>`; a keystore that cuts on rotation) makes the signature
//!   cacheable under that same thread — a rotation cuts the key, and the cached
//!   signature goes with it ([`a_rotated_key_is_cut_and_the_signature_recomputes`]);
//! - a key served UNCACHEABLE (a secret resource that must hit the store every
//!   time) makes the signature uncacheable: every call recomputes, nothing is
//!   stale, and nothing is ever served from the cache
//!   ([`over_a_live_keystore_nothing_is_cached`]).
//!
//! The module marks both results `.cacheable()` and declares no thread of its own:
//! it holds no key material and has no rotation to watch, so the thread is the
//! keystore's to name and to cut. [`conforms`] walks the threaded keystore, where
//! the suite can hold `sign` and `verify` to a cache hit, byte-identical results
//! and a non-empty thread set; neither is declared `pure`, so an empty thread set
//! (a signature cached forever, surviving a key rotation) would be a finding.
//!
//! The walk covers the fixture too: the suite walks EVERYTHING the kernel binds,
//! the key resources included, so [`Key`] describes itself the way a module
//! endpoint must (a kebab-case id, a Source action, an output). A bare `Endpoint`
//! with the default `describe()` is reported as declaring no action — the first
//! run's third finding was exactly that, on the fixture.
//!
//! ## Fixtures
//!
//! The suite's minimal inputs (`x`, `urn:example:conformance`) are not a key IRI
//! or a signature-graph, so each action takes a [`Fixture`]: `sign` the private
//! key's IRI, `verify` a graph this file signs first plus the matching public key.
//! [`conforms`] runs once per algorithm — Ed25519 and ES256 — so the `text/turtle`
//! face is checked with BOTH `sig:signer` encodings (a raw key, an SPKI document).
//!
//! ## The `sig:` namespace
//!
//! The signature-graph's terms live under `https://ikigai-rs.dev/ns/sign#`
//! ([`ikigai_sign::SIG_NS`]) — this crate's own, named in its README and
//! registered with `Suite::namespace`, so VOCABULARY holds the face to `rdf:` plus
//! that namespace and nothing else. What the check cannot see: the namespace is
//! defined by this crate's documentation, not served as a vocabulary document.
//!
//! No opt-outs, and NAMES runs: both ids are kebab-case.

use async_trait::async_trait;
use ikigai_conformance::{Check, Fixture, Report, Suite};
use ikigai_core::{
    ArgRef, Capability, Description, Endpoint, Exact, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Result as CoreResult, Verb,
};
use std::sync::{Arc, RwLock};

/// The two endpoints `space()` binds, by description id.
const SIGN: &str = "sign";
const VERIFY: &str = "verify";

/// Where the fixture binds the keypair. Each doubles as the golden thread the
/// threaded keystore names for it — the `ikigai-fs` convention (`depends_on` the
/// resource's own IRI), so a cut is keyed on the name the caller resolved.
const PRIVATE_IRI: &str = "urn:conformance:key:private";
const PUBLIC_IRI: &str = "urn:conformance:key:public";

/// The bytes every fired action signs or verifies.
const MESSAGE: &str = "conformance";

/// A keypair in the standard encodings the module consumes: PKCS8 private, SPKI
/// public, PEM. Fixed keys keep the walk deterministic and RNG-free.
struct Keypair {
    private: &'static str,
    public: &'static str,
    /// What the emitted graph's `sig:algorithm` must say.
    algorithm: &'static str,
}

/// `openssl genpkey -algorithm ed25519`.
const ED25519: Keypair = Keypair {
    private: "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIEIW/m80W4IrD82k3Mos0l4aeyfOkZMMZXqEYt6jpawc\n\
-----END PRIVATE KEY-----\n",
    public: "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAa9JuLzyLESJBF9LPZZ4RJk13iu5OhgKvLRQ3q0oQ4pE=\n\
-----END PUBLIC KEY-----\n",
    algorithm: "Ed25519",
};

/// A P-256 key from a fixed scalar — the algorithm the Secure Enclave speaks, here
/// as a software key exercising the same dispatch.
const ES256: Keypair = Keypair {
    private: "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBwcHBwcHBwcHBwcH\n\
BwcHBwcHBwcHBwcHBwcHBwcHBwehRANCAAQeGFMv1HVMAvMEHZx1zrM7g//YGsfO\n\
T+iCzLHJi8WJbqRsMRxOL/QN2Wo2U+bkVEXTLf5Ibs7XXHqQxqGIgcCj\n\
-----END PRIVATE KEY-----\n",
    public: "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHhhTL9R1TALzBB2cdc6zO4P/2BrH\n\
zk/ogsyxyYvFiW6kbDEcTi/0DdlqNlPm5FRF0y3+SG7O11x6kMahiIHAow==\n\
-----END PUBLIC KEY-----\n",
    algorithm: "ES256",
};

/// A key resource — what `urn:file:<pem>` or `urn:secret:<name>` is to the module:
/// key bytes behind an IRI, resolved through the kernel. `thread` is the golden
/// thread a keystore that can be rotated names (and cuts on rotation); `None` is a
/// live store that must be read every time, and serves the key uncacheable. The
/// PEM sits behind a lock so a test can rotate the key in place.
struct Key {
    id: &'static str,
    pem: Arc<RwLock<&'static str>>,
    thread: Option<&'static str>,
}

#[async_trait]
impl Endpoint for Key {
    async fn invoke(&self, _inv: &Invocation<'_>) -> CoreResult<Representation> {
        let pem = *self.pem.read().expect("key lock");
        let repr = Representation::new(
            ReprType::new("application/x-pem-file"),
            pem.as_bytes().to_vec(),
        );
        Ok(match self.thread {
            Some(thread) => repr.cacheable().depends_on(thread),
            None => repr,
        })
    }

    fn name(&self) -> &str {
        self.id
    }

    /// The suite walks this endpoint beside the module's, so it carries the same
    /// contract a module endpoint must: an id, a Source action, an output.
    fn describe(&self) -> Description {
        Description::new(self.id)
            .title("Conformance key resource")
            .summary("A PKCS8/SPKI key in PEM, served as a kernel resource for the walk.")
            .verb(Verb::Source)
            .output("application/x-pem-file")
    }
}

/// The module's space with one keypair bound as kernel resources, and a handle to
/// the private key so a test can rotate it. `threaded` selects the keystore's kind
/// (see the file docs): every key under a golden thread named after its IRI, or
/// every key live.
fn keystore(keys: &Keypair, threaded: bool) -> (Kernel, Arc<RwLock<&'static str>>) {
    let private = Arc::new(RwLock::new(keys.private));
    let thread = |iri: &'static str| threaded.then_some(iri);
    let space = ikigai_sign::space()
        .bind(
            Exact::new(PRIVATE_IRI),
            Key {
                id: "key-private",
                pem: Arc::clone(&private),
                thread: thread(PRIVATE_IRI),
            },
        )
        .bind(
            Exact::new(PUBLIC_IRI),
            Key {
                id: "key-public",
                pem: Arc::new(RwLock::new(keys.public)),
                thread: thread(PUBLIC_IRI),
            },
        );
    (Kernel::new(Arc::new(space)), private)
}

fn sign_request(message: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:sign:sign").unwrap())
        .with_arg("in", ArgRef::Inline(message.as_bytes().to_vec()))
        .with_arg("key", ArgRef::Inline(PRIVATE_IRI.as_bytes().to_vec()))
}

fn verify_request(message: &str, graph: &str) -> Request {
    Request::new(Verb::Source, Iri::parse("urn:sign:verify").unwrap())
        .with_arg("in", ArgRef::Inline(message.as_bytes().to_vec()))
        .with_arg("sig", ArgRef::Inline(graph.as_bytes().to_vec()))
        .with_arg("key", ArgRef::Inline(PUBLIC_IRI.as_bytes().to_vec()))
}

/// The capability a signer holds: `urn:cap:sign` and nothing else.
fn signer() -> Capability {
    Capability::scoped([ikigai_sign::CAP_SIGN])
}

fn issue(kernel: &Kernel, request: Request, capability: &Capability) -> Representation {
    futures::executor::block_on(kernel.issue(request, capability))
        .unwrap_or_else(|e| panic!("resolution failed: {e}"))
}

/// Sign `message` through the kernel under the signer's capability, returning the
/// signature-graph Turtle.
fn sign(kernel: &Kernel, message: &str) -> String {
    String::from_utf8(issue(kernel, sign_request(message), &signer()).bytes).unwrap()
}

/// The suite, configured for this module (see the file docs for why each line):
/// the module's namespace, and one fixture per action.
fn suite(graph: &str) -> Suite {
    Suite::new()
        .namespace(ikigai_sign::SIG_NS)
        .fixture(
            Fixture::new(SIGN, Verb::Source)
                .arg("in", MESSAGE)
                .arg("key", PRIVATE_IRI),
        )
        .fixture(
            Fixture::new(VERIFY, Verb::Source)
                .arg("in", MESSAGE)
                .arg("sig", graph)
                .arg("key", PUBLIC_IRI),
        )
}

/// The walk saw the two module endpoints and the two fixture keys, one Source
/// action each, and skipped nothing. A third module endpoint bound without a line
/// here would be held to a weaker standard; a declared id that binds nothing is a
/// stale list.
fn assert_shape(report: &Report) {
    assert_eq!(
        report.endpoints, 4,
        "sign, verify, key-private, key-public: {report}"
    );
    assert_eq!(report.actions, 4, "one Source action each: {report}");
    assert_eq!(
        report.checks.skipped().count(),
        0,
        "every check runs: {report}"
    );
}

#[test]
fn conforms() {
    for keys in [&ED25519, &ES256] {
        let (kernel, _) = keystore(keys, true);
        let graph = sign(&kernel, MESSAGE);
        assert!(
            graph.contains(&format!("sig:algorithm \"{}\"", keys.algorithm)),
            "{graph}"
        );
        let report = suite(&graph)
            .cacheable(SIGN)
            .cacheable(VERIFY)
            .run_blocking(&kernel);
        // Printed even when clean (`--nocapture`): the report is the record.
        eprintln!("[{} keystore]\n{report}", keys.algorithm);
        assert!(report.is_clean(), "{}: {report}", keys.algorithm);
        assert_shape(&report);
    }
}

/// The other keystore: keys served uncacheable, as a secret backend that must hit
/// its store on every read would serve them. The module still says `.cacheable()`,
/// and the kernel hands the results back uncacheable — the effective expiry is the
/// key's. Undeclared, that is correct and the walk is clean (nothing stale can be
/// served); DECLARED, the suite reports the downgrade on both endpoints, which is
/// the only way the ~2000× incident becomes visible — the types are identical
/// either way.
#[test]
fn over_a_live_keystore_nothing_is_cached() {
    let (kernel, _) = keystore(&ED25519, false);
    let graph = sign(&kernel, MESSAGE);

    let report = suite(&graph).run_blocking(&kernel);
    eprintln!("[live keystore, undeclared]\n{report}");
    assert!(report.is_clean(), "{report}");
    assert_shape(&report);
    assert!(
        !kernel.is_cached(&sign_request(MESSAGE), &signer()),
        "a signature over an uncacheable key is not cached"
    );

    let report = suite(&graph)
        .cacheable(SIGN)
        .cacheable(VERIFY)
        .run_blocking(&kernel);
    eprintln!("[live keystore, declared cacheable]\n{report}");
    let downgraded: Vec<&str> = report
        .of(Check::Cacheable)
        .map(|f| f.endpoint.as_str())
        .collect();
    assert_eq!(downgraded, [SIGN, VERIFY], "{report}");
    for finding in report.of(Check::Cacheable) {
        assert!(
            finding.detail.contains("declared cacheable"),
            "the finding names the declaration: {finding}"
        );
    }
    assert_eq!(report.findings.len(), 2, "and nothing else: {report}");
}

/// The half the suite cannot see: the thread a signature inherits is a name the
/// KEYSTORE cuts. This module has no watcher and no key material, so after a
/// rotation with no cut the cached signature — made with the old key — is served;
/// the keystore cutting the thread it declared (the key's own IRI) is what
/// recomputes it. The rotation swaps algorithms so the recomputation is visible in
/// the bytes: a deterministic re-sign under the SAME key would be byte-identical
/// to the stale one, and prove nothing.
#[test]
fn a_rotated_key_is_cut_and_the_signature_recomputes() {
    let (kernel, private) = keystore(&ED25519, true);

    let first = sign(&kernel, MESSAGE);
    assert!(first.contains("sig:algorithm \"Ed25519\""), "{first}");
    assert!(
        kernel.is_cached(&sign_request(MESSAGE), &signer()),
        "over a threaded key the signature is cached"
    );

    // The operator rotates the key in the store. Nothing in this module notices.
    *private.write().expect("key lock") = ES256.private;
    let stale = sign(&kernel, MESSAGE);
    assert_eq!(
        stale, first,
        "no watcher here: a rotation with no cut is served from the cache"
    );

    // The keystore cuts the thread it named — the key's IRI — and the signature
    // that depended on it goes with it.
    kernel.cut(PRIVATE_IRI);
    let fresh = sign(&kernel, MESSAGE);
    assert!(
        fresh.contains("sig:algorithm \"ES256\""),
        "recomputed with the rotated key after the cut: {fresh}"
    );
    assert_ne!(fresh, first);
}

/// What `ikigai-conformance` 0.1.0 does not check (its PENDING #11): a declared
/// output that is not an RDF face is never compared with what the action serves.
/// Read by hand, then pinned: `sign` declares and serves `text/turtle`, `verify`
/// declares and serves `text/plain` (each with a `charset` parameter the
/// comparison ignores).
#[test]
fn declared_outputs_are_the_media_types_served() {
    let (kernel, _) = keystore(&ED25519, true);
    let graph = sign(&kernel, MESSAGE);
    let served = [
        (
            "urn:sign:sign",
            issue(&kernel, sign_request(MESSAGE), &signer()),
        ),
        (
            "urn:sign:verify",
            issue(
                &kernel,
                verify_request(MESSAGE, &graph),
                &Capability::root(),
            ),
        ),
    ];
    for (iri, repr) in served {
        let description = kernel
            .describe_pattern(iri)
            .unwrap_or_else(|| panic!("{iri} describes itself"));
        let got = ikigai_conformance::rdf::bare_media_type(&repr.repr_type.media_type);
        let declared: Vec<String> = description
            .outputs
            .iter()
            .map(|o| ikigai_conformance::rdf::bare_media_type(o))
            .collect();
        assert!(
            declared.contains(&got),
            "{iri} served `{got}`, declared only {declared:?}"
        );
        assert_eq!(declared.len(), 1, "{iri} declares exactly one face");
    }
}
