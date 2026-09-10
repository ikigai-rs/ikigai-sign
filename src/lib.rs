//! `ikigai-sign` — a capability-gated, **crypto-agile signing + verification** module, where a
//! signature is an **RDF graph** and keys are **kernel-resolved resources**. Two algorithms
//! today — **Ed25519** and **ES256** (ECDSA P-256, the algorithm the Secure Enclave and TPMs
//! speak) — selected by the key and dispatched on `sig:algorithm`; a third is a new id plus a
//! signer/verifier, never a restructure.
//!
//! Two endpoints, mounted by [`space`]:
//!
//! 1. **`urn:sign:sign`** (Source, **requires `urn:cap:sign`**) — sign arbitrary bytes.
//!    Inputs: `in` = the bytes to sign (piped `content` fallback) + `key` = the **URI** of a
//!    PKCS8 **private** key resource — Ed25519 **or** P-256; the algorithm is discovered from
//!    the key, never stated by the caller. The key is dereferenced **through the kernel**
//!    (`inv.source` on the URI, cap-scoped) — so `key=urn:file:my.pem` works today and
//!    `key=urn:secret:…` works unchanged the moment a secrets backend exists. Output is a
//!    **deterministic** RDF signature-graph (`text/turtle`): a `sig:Signature` with
//!    `sig:algorithm`, `sig:signer` (base64 public key), `sig:value` (base64 signature), and
//!    `sig:contentHash` (**`sha256:<hex>`** — the digest names its algorithm, see
//!    [`HASH_ALG_SHA256`]). No timestamp — both algorithms sign deterministically (Ed25519 by
//!    construction, ES256 via RFC 6979), so the same
//!    `(bytes, key)` yields byte-identical Turtle, and the graph is
//!    content-addressable/cacheable. The signature node is **skolemized** to a stable IRI
//!    content-addressed on the signature and **tagged with the digest algorithm that
//!    addressed it** — `urn:sign:sha256:<hex>` (see [`HASH_ALG_SHA256`]); no blank nodes.
//!
//! 2. **`urn:sign:verify`** (Source, **open** — no capability) — verify bytes against a
//!    signature-graph. Inputs: `in` = the bytes, `sig` = the signature-graph (piped `content`
//!    fallback), `key` = the URI of a SPKI **public** key resource — Ed25519 or P-256, matching
//!    the graph's `sig:algorithm` (kernel-resolved).
//!    It parses the graph, recomputes the content hash of `in` and compares it to the graph's
//!    `sig:contentHash` (an UNTAGGED digest is read as SHA-256, so records signed before the
//!    tag existed still verify; an unrecognised tag is refused, never assumed), then
//!    **dispatches on the graph's `sig:algorithm`** and verifies with that algorithm against the
//!    public key. Output is `text/plain`: a clear `valid` / `invalid`
//!    verdict. A signature that simply does not check out is **not an error** — it is a `valid:
//!    …` / `invalid: …` answer (`Ok`); only a malformed graph / unreadable key / missing field
//!    is an `Err`. Never panics on hostile input. **The node's IRI is never read** — see
//!    the private `parse_sig_graph` — so a graph minted under either spelling of the name verifies the
//!    same way, and the tagging of the identifier in 0.2.1 was a discontinuity in a naming
//!    scheme, not a migration.
//!
//! ## Keys
//!
//! Standard **PKCS8** (private) and **SPKI** (public) keys, in PEM or DER, of either supported
//! algorithm — exactly what `openssl genpkey -algorithm ed25519` and `openssl ecparam -name
//! prime256v1 -genkey` emit, and what a `urn:secret:*` custody backend will serve. The caller
//! never names an algorithm: on the sign side it is discovered by which PKCS8 parser accepts
//! the key (the AlgorithmIdentifier OID makes that unambiguous), and on the verify side it is
//! read from the graph's `sig:algorithm`, with the supplied public key expected to match.
//! This module only **consumes** keys; **key generation is out of scope** (it
//! belongs to the secrets module, which owns the key lifecycle — HSM/passkey keys are
//! generated non-exportably and would sign via a delegated act, not here).
//!
//! ## Cacheability
//!
//! Both results are marked `.cacheable()` — signing is deterministic, verification is a pure
//! function of graph + bytes + key — and neither declares a golden thread of its own. The key
//! is the only state either reads, it is read THROUGH the kernel, and the kernel folds the key
//! resolution's expiry and threads into the result: **a signature is exactly as cacheable as
//! its key.** A keystore that serves keys under a thread (an `ikigai-fs` cacheable mount, a
//! store that cuts on rotation) gets signatures that cache until the key rotates; one that
//! serves keys uncacheable (a secret backend read on every call) gets signatures that
//! recompute every call. This module holds no key material and watches nothing, so the
//! thread is the keystore's to name and to cut — `tests/conformance.rs` pins both halves, and
//! runs `ikigai-conformance` over [`space`] under both keystore kinds and both algorithms.
//!
//! ## The `sig:` vocabulary
//!
//! Self-contained in this crate under `https://ikigai-rs.dev/ns/sign#` (see [`SIG_NS`]), and
//! deliberately **not** part of the shared `ikigai-rs.dev/ns` vocabulary — so no `/ns` deploy
//! is owed. The `sig:Signature` / `sig:algorithm` / `sig:signer` / `sig:value` /
//! `sig:contentHash` terms are the ones to promote if it graduates. `ikigai-conformance`'s
//! VOCABULARY check knows the namespace as this crate's own (`Suite::namespace`); it is
//! defined by this documentation and the README, not served as a vocabulary document.
//!
//! **A second producer exists** as of 2026-08-23: `ikigai-log`'s `#seal` lines carry
//! `sig:contentHash` / `sig:value` rather than minting parallel terms. That is exactly why the
//! digest here is tagged (`sha256:<hex>`) — sharing a predicate while writing two lexical forms
//! of the same value means the two never join in a query, which is a silent failure, not a
//! loud one.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use base64::Engine as _;
use ed25519_dalek::pkcs8::{spki::DecodePublicKey, DecodePrivateKey};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
// The `signature` crate's traits, implemented by BOTH algorithms' keys — imported once and
// used for Ed25519 and ES256 alike (this is the crypto-agility, at the trait level).
use ikigai_core::{
    ArgSpec, Description, Endpoint, EndpointSpace, Error as CoreError, Exact, Invocation, Iri,
    ReprType, Representation, Request, Result as CoreResult, Verb,
};
use oxrdf::Term;
use oxrdfio::{RdfFormat, RdfParser};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};

/// The capability gating "may sign at all." Declared on `urn:sign:sign` via
/// [`Description::requires`], and so enforced by the kernel *before dispatch* (core 0.1.49
/// onward: declared = enforced is the kernel's baseline, on the same predicate selection and
/// `urn:kernel:validate` use). The endpoint re-checks it at entry as a second line — that
/// check earns its keep only where no kernel gate ran, on a detached invocation or a module
/// shim, and it costs one string comparison.
pub const CAP_SIGN: &str = "urn:cap:sign";

/// The signature vocabulary namespace. Self-contained in this crate (no `/ns` deploy).
pub const SIG_NS: &str = "https://ikigai-rs.dev/ns/sign#";

/// `sig:Signature` — the class of the signature node.
const SIG_SIGNATURE: &str = "https://ikigai-rs.dev/ns/sign#Signature";
/// `sig:algorithm` — the signature algorithm id: [`ALG_ED25519`] or [`ALG_ES256`], chosen by
/// the key the signer was parsed from. **Not a constant.** It was `Ed25519` for every graph
/// this module emitted before 0.2.0; since 0.2.0 `urn:sign:sign` dispatches on key type and
/// verification dispatches on this literal, so a consumer branching on it has two arms to
/// write and a third to refuse. (Refuse, do not assume: an unknown algorithm read as Ed25519
/// would mint a confident verdict on a check that never happened — the same reasoning as
/// [`content_hash_sha256_hex`]'s unknown-tag arm.)
const SIG_ALGORITHM: &str = "https://ikigai-rs.dev/ns/sign#algorithm";
/// `sig:signer` — the base64-encoded public key of the signer, **in this algorithm's own
/// encoding**: a raw 32-byte key for `Ed25519`, an SPKI DER document for `ES256`. The two are
/// not interchangeable and the length does not identify them — read `sig:algorithm` first.
const SIG_SIGNER: &str = "https://ikigai-rs.dev/ns/sign#signer";
/// `sig:value` — the base64-encoded 64-byte signature: Ed25519's `R‖S`, or ES256's `r‖s`
/// (fixed-width, not DER — the Enclave's DER output is normalised at the sign-through
/// boundary). Same width for both algorithms, so the width proves nothing about which.
const SIG_VALUE: &str = "https://ikigai-rs.dev/ns/sign#value";
/// `sig:contentHash` — the **algorithm-tagged** digest of the signed bytes: `sha256:<hex>`.
const SIG_CONTENT_HASH: &str = "https://ikigai-rs.dev/ns/sign#contentHash";

/// The digest-algorithm tag every emitted digest carries — in `sig:contentHash`
/// (`sha256:<hex>`) and, since 0.2.1, in the signature node's own IRI
/// (`urn:sign:sha256:<hex>`).
///
/// A digest that escapes the process names its algorithm, because a bare hex string is a
/// permanent, unrecoverable commitment to one hash function: nothing in the graph says what
/// produced it, and a verifier years later can only guess. The tag is a TEXT prefix (not
/// multihash bytes) so the literal stays greppable and joins by string equality with the same
/// predicate written elsewhere — `ikigai-log`'s seals carry `sig:contentHash` too, tagged.
///
/// Exactly one spelling is emitted and exactly one is accepted: lowercase `sha256:`. An
/// untagged literal is the pre-0.2 form and reads as SHA-256 (verification accepts it, for
/// back-compat with records signed before the tag existed); any OTHER tag is refused rather
/// than assumed.
///
/// An IDENTIFIER made of an untagged digest is the same commitment, only harder to walk back:
/// a literal can be rewritten by a later producer, but a name is quoted, stored and referred
/// to elsewhere. So the node IRI carries the tag as well — see the private `sign_to_graph`.
///
/// Public so a second producer of `sig:contentHash` writes the tag from THIS definition rather
/// than from a copy of the string.
pub const HASH_ALG_SHA256: &str = "sha256";

/// `rdf:type`.
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
/// The RDF namespace, for the emitted `@prefix rdf:` line.
const RDF_NS: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

/// The signature-algorithm ids, as they appear in `sig:algorithm`. The whole module dispatches
/// on this string — the crypto-agile contract — so a new algorithm is a new id plus a signer
/// and verifier for it, never a restructure. The Secure Enclave speaks [`ALG_ES256`].
const ALG_ED25519: &str = "Ed25519";
const ALG_ES256: &str = "ES256";

/// The signature-graph output media type.
const MEDIA_TURTLE: &str = "text/turtle";
/// The verify verdict output media type.
const MEDIA_PLAIN: &str = "text/plain";
/// The XSD `string` datatype IRI — the `class` of the string-valued args.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
/// The `class` of the `key` arg: a resource (an IRI naming a key), not a scalar.
const RDFS_RESOURCE: &str = "http://www.w3.org/2000/01/rdf-schema#Resource";

/// The standard base64 alphabet (RFC 4648, with padding) used for `sig:signer`/`sig:value`.
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// =====================================================================================
// The pure core: hashing, key parsing, sign, verify, and the sig-graph codec — all
// kernel-free and total (never panic). The endpoints below are the only kernel-aware layer.
// =====================================================================================

/// The lowercase-hex SHA-256 of `bytes` — the digest itself, untagged.
fn content_hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    to_hex(&digest)
}

/// The value written to `sig:contentHash`: the SHA-256 of `bytes`, **tagged** — `sha256:<hex>`.
fn tagged_content_hash(bytes: &[u8]) -> String {
    format!("{HASH_ALG_SHA256}:{}", content_hash_hex(bytes))
}

/// Read a `sig:contentHash` literal as a SHA-256 hex digest, or say why it cannot be.
///
/// Three cases, and the middle one is the whole point of tagging:
///
/// * `sha256:<hex>` — the current form; the hex is returned.
/// * `<hex>` with no tag — a **pre-0.2 graph**, from before digests were tagged. SHA-256 was
///   the only algorithm this module ever emitted, so reading it as SHA-256 recovers exactly
///   what the producer meant. This is the back-compat path, and it is load-bearing: real
///   signed records exist in that form and must keep verifying.
/// * any other tag (`blake3:…`) — `Err(tag)`. The caller REFUSES. Verifying a blake3 digest
///   as SHA-256 would make the tag decorative — worse than no tag, because it would mint a
///   confident `valid` verdict on a comparison that never happened.
fn content_hash_sha256_hex(literal: &str) -> Result<&str, &str> {
    match literal.split_once(':') {
        None => Ok(literal),
        Some((tag, hex)) if tag == HASH_ALG_SHA256 => Ok(hex),
        Some((tag, _)) => Err(tag),
    }
}

/// Lowercase hex of a byte slice (no dependency, deterministic).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// A private signing key of a supported algorithm, parsed from PKCS8 (PEM or DER). The
/// algorithm is DISCOVERED by which parser accepts the key — the sign path never assumes one.
/// Add an algorithm by adding a variant and a parse attempt; the rest of sign is unchanged.
enum AnySigner {
    Ed25519(Box<SigningKey>),
    Es256(Box<P256SigningKey>),
}

impl AnySigner {
    /// Parse a PKCS8 private key, trying each supported algorithm. The PKCS8 AlgorithmIdentifier
    /// OID makes this unambiguous — only the matching parser accepts the key.
    fn parse(bytes: &[u8]) -> Result<AnySigner, String> {
        let ed = match as_pem(bytes) {
            Some(pem) => SigningKey::from_pkcs8_pem(pem),
            None => SigningKey::from_pkcs8_der(bytes),
        };
        if let Ok(k) = ed {
            return Ok(AnySigner::Ed25519(Box::new(k)));
        }
        let ec = match as_pem(bytes) {
            Some(pem) => P256SigningKey::from_pkcs8_pem(pem),
            None => P256SigningKey::from_pkcs8_der(bytes),
        };
        match ec {
            Ok(k) => Ok(AnySigner::Es256(Box::new(k))),
            Err(e) => Err(format!(
                "not a PKCS8 Ed25519 or P-256 (ES256) private key (P-256 parse: {e})"
            )),
        }
    }

    /// The `sig:algorithm` id for this key.
    fn algorithm(&self) -> &'static str {
        match self {
            AnySigner::Ed25519(_) => ALG_ED25519,
            AnySigner::Es256(_) => ALG_ES256,
        }
    }

    /// Sign `message`, returning `(base64 signature, base64 public key)` in this algorithm's
    /// encoding. Ed25519 is UNCHANGED on the wire — a raw 32-byte public key and a 64-byte
    /// signature. ES256 uses a 64-byte r‖s signature (the Enclave's DER output is normalised to
    /// this at the sign-through boundary) and an SPKI-DER public key (self-describing).
    fn sign(&self, message: &[u8]) -> Result<(String, String), String> {
        match self {
            AnySigner::Ed25519(k) => {
                let sig: Signature = k.sign(message);
                Ok((
                    B64.encode(sig.to_bytes()),
                    B64.encode(k.verifying_key().to_bytes()),
                ))
            }
            AnySigner::Es256(k) => {
                let sig: P256Signature = k.sign(message);
                let spki = k
                    .verifying_key()
                    .to_public_key_der()
                    .map_err(|e| format!("cannot encode the P-256 public key: {e}"))?;
                Ok((B64.encode(sig.to_bytes()), B64.encode(spki.as_bytes())))
            }
        }
    }
}

/// This key's `sig:signer` encoding for the Ed25519 algorithm — the raw 32-byte public key,
/// base64. Kept as a free function so the verify-side pre-check encodes identically to `sign`.
fn ed25519_signer_b64(key: &VerifyingKey) -> String {
    B64.encode(key.to_bytes())
}

/// Parse SPKI Ed25519 **public** key material — PEM or DER. Clear message on failure; no panic.
fn parse_ed25519_public(bytes: &[u8]) -> Result<VerifyingKey, String> {
    match as_pem(bytes) {
        Some(pem) => VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| format!("not a valid SPKI Ed25519 public key (PEM): {e}")),
        None => VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| format!("not a valid SPKI Ed25519 public key (DER): {e}")),
    }
}

/// Parse SPKI P-256 **public** key material — PEM or DER. Clear message on failure; no panic.
fn parse_p256_public(bytes: &[u8]) -> Result<P256VerifyingKey, String> {
    match as_pem(bytes) {
        Some(pem) => P256VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| format!("not a valid SPKI P-256 public key (PEM): {e}")),
        None => P256VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| format!("not a valid SPKI P-256 public key (DER): {e}")),
    }
}

/// View `bytes` as a PEM string iff they are UTF-8 beginning (after leading whitespace) with a
/// `-----BEGIN` armor line; otherwise `None` (treat as DER). Keeps the PEM/DER split total.
fn as_pem(bytes: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.trim_start().starts_with("-----BEGIN") {
        Some(s)
    } else {
        None
    }
}

/// Sign `message` with `signer`, returning the deterministic RDF **signature-graph** as
/// canonical Turtle. Pure and deterministic (both Ed25519 and ES256 sign deterministically):
/// same `(message, key)` ⇒ byte-identical output. Algorithm-agnostic — it records whatever
/// `signer` reports.
fn sign_to_graph(message: &[u8], signer: &AnySigner) -> Result<String, String> {
    let (sig_b64, signer_b64) = signer.sign(message)?;
    let algorithm = signer.algorithm();
    let content_hash = tagged_content_hash(message);

    // Skolemize: the node IRI is content-addressed on the (deterministic) signature bytes, so
    // the graph is stable and diffable and carries no blank node. WHAT it is derived from —
    // sha256 over the BASE64 TEXT of the signature — is load-bearing (see `verify_ed25519`:
    // verification must admit exactly one valid signature per (message, key), or this name is
    // forgeable), and the tag does not touch it: 0.2.1 added an algorithm label to the name,
    // it did not re-derive the name. A name is a harder commitment than a literal — a literal
    // can be rewritten by a later producer, a name is quoted and pointed at — so the digest
    // that addresses the node says which digest it is, exactly as `sig:contentHash` does.
    //
    // ⚠ The PREIMAGE is the base64 text, not the raw signature bytes, and that is an
    // encoding-dependent choice made by accident: 0.1.0 hashed `signature.to_bytes()`, and the
    // crypto-agility refactor in 0.2.0 moved to the base64 string without noticing, because
    // nothing pinned the derivation and nothing reads the subject. The 2026-08-07 public
    // record's node (`7b6c919e…`) is sha256 of that record's RAW signature bytes; this code
    // would mint `fbb203be…` for the same signature. Both name the same signature, so nothing
    // broke — but changing the base64 alphabet or padding would move every future name again.
    // `the_node_iri_is_tagged_and_still_addresses_the_signature` now pins whichever preimage
    // is in force, so the next such move has to be deliberate.
    //
    // The `sha256:` segment does not collide with the module's own `Exact` bindings
    // (`urn:sign:sign`, `urn:sign:verify`) — a hex digest never could either, but a tagged
    // name is positively distinguishable rather than merely accidentally distinct: everything
    // under `urn:sign:<alg>:` is a signature node, everything else under `urn:sign:` is an
    // endpoint.
    let node = format!(
        "urn:sign:{HASH_ALG_SHA256}:{}",
        to_hex(&Sha256::digest(sig_b64.as_bytes()))
    );

    let mut out = String::new();
    out.push_str(&format!("@prefix rdf: <{RDF_NS}> .\n"));
    out.push_str(&format!("@prefix sig: <{SIG_NS}> .\n"));
    out.push_str(&format!("<{node}> rdf:type sig:Signature .\n"));
    out.push_str(&format!(
        "<{node}> sig:algorithm {} .\n",
        turtle_string(algorithm)
    ));
    out.push_str(&format!(
        "<{node}> sig:signer {} .\n",
        turtle_string(&signer_b64)
    ));
    out.push_str(&format!(
        "<{node}> sig:value {} .\n",
        turtle_string(&sig_b64)
    ));
    out.push_str(&format!(
        "<{node}> sig:contentHash {} .\n",
        turtle_string(&content_hash)
    ));
    Ok(out)
}

/// Render a Rust string as a Turtle string literal, escaping the reserved characters so the
/// value cannot terminate the literal early or inject syntax. (base64/hex never need it, but a
/// signer/algorithm value stays safe regardless.)
fn turtle_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The fields extracted from a parsed signature-graph.
struct SigFields {
    algorithm: String,
    value_b64: String,
    content_hash: String,
    /// `sig:signer` (base64 public key), informational — verification uses the caller's `key`.
    signer_b64: Option<String>,
}

/// Parse a signature-graph (Turtle) into its [`SigFields`], reading the literals of the single
/// `sig:Signature`. Any parse failure or missing required field is a clear `Err`; never panics.
///
/// **The subject IRI is never read** — only predicates and objects are. The node's name is an
/// output of signing, not an input to verification, so a graph minted before the name carried
/// its digest tag (`urn:sign:<hex>`) verifies exactly like one minted after it
/// (`urn:sign:sha256:<hex>`); there is nothing to migrate and nothing joins the two forms.
fn parse_sig_graph(turtle: &str) -> Result<SigFields, String> {
    let mut algorithm: Option<String> = None;
    let mut value_b64: Option<String> = None;
    let mut content_hash: Option<String> = None;
    let mut signer_b64: Option<String> = None;
    let mut saw_signature = false;

    for quad in RdfParser::from_format(RdfFormat::Turtle).for_slice(turtle.as_bytes()) {
        let quad = quad.map_err(|e| format!("signature-graph parse error: {e}"))?;
        let predicate = quad.predicate.as_str();
        match predicate {
            RDF_TYPE => {
                if let Term::NamedNode(n) = &quad.object {
                    if n.as_str() == SIG_SIGNATURE {
                        saw_signature = true;
                    }
                }
            }
            SIG_ALGORITHM => algorithm = literal_value(&quad.object).or(algorithm),
            SIG_VALUE => value_b64 = literal_value(&quad.object).or(value_b64),
            SIG_CONTENT_HASH => content_hash = literal_value(&quad.object).or(content_hash),
            SIG_SIGNER => signer_b64 = literal_value(&quad.object).or(signer_b64),
            _ => {}
        }
    }

    if !saw_signature {
        return Err(format!(
            "no `sig:Signature` (`<{SIG_SIGNATURE}>`) node in the signature-graph"
        ));
    }
    Ok(SigFields {
        algorithm: algorithm.ok_or("signature-graph missing sig:algorithm")?,
        value_b64: value_b64.ok_or("signature-graph missing sig:value")?,
        content_hash: content_hash.ok_or("signature-graph missing sig:contentHash")?,
        signer_b64,
    })
}

/// The lexical value of a literal object, or `None` for a non-literal term.
fn literal_value(term: &Term) -> Option<String> {
    match term {
        Term::Literal(l) => Some(l.value().to_string()),
        _ => None,
    }
}

/// The outcome of a verification: a clear valid/invalid verdict with a reason.
enum Verdict {
    Valid {
        algorithm: String,
        signer_b64: String,
    },
    Invalid {
        reason: String,
    },
}

impl Verdict {
    /// The `text/plain` rendering — `valid: …` / `invalid: …`.
    fn render(&self) -> String {
        match self {
            Verdict::Valid {
                algorithm,
                signer_b64,
            } => {
                format!("valid: signed by {signer_b64} (algorithm {algorithm})\n")
            }
            Verdict::Invalid { reason } => format!("invalid: {reason}\n"),
        }
    }
}

/// Verify `message` against a parsed signature-graph, using the caller's `key` bytes. Dispatch
/// is on the graph's `sig:algorithm` — the crypto-agile seam — and the public key is parsed AS
/// that algorithm, so a key/algorithm mismatch is a clear error. A signature that simply
/// doesn't check out is a normal `Invalid` answer, not an `Err`; `Err` is reserved for a graph
/// or key too malformed to turn into a verification (a shape problem, not a verdict).
fn verify_message(message: &[u8], fields: &SigFields, key_bytes: &[u8]) -> Result<Verdict, String> {
    // Content-hash pre-check, signature-algorithm-agnostic: a clear verdict when the bytes
    // differ from what was signed (the crypto check below would also fail, but less legibly).
    //
    // The graph's digest names its own algorithm (`sha256:<hex>`), so compare like with like:
    // strip the tag, then compare hex to hex. An untagged literal is a pre-0.2 graph and reads
    // as SHA-256; an unrecognised tag STOPS here with a verdict rather than falling through to
    // the crypto check — a signature verifies the BYTES, so it would happily say `valid` on a
    // digest this module never checked, and the tag would be decoration.
    let recomputed = content_hash_hex(message);
    let signed_hex = match content_hash_sha256_hex(&fields.content_hash) {
        Ok(hex) => hex,
        Err(tag) => {
            return Ok(Verdict::Invalid {
                reason: format!(
                    "unsupported content-hash algorithm `{tag}` in sig:contentHash \
                     (this module computes {HASH_ALG_SHA256}); refusing to assume it is \
                     {HASH_ALG_SHA256}"
                ),
            })
        }
    };
    if recomputed != signed_hex {
        return Ok(Verdict::Invalid {
            reason: format!(
                "content hash mismatch (signed {}, got {HASH_ALG_SHA256}:{recomputed})",
                fields.content_hash
            ),
        });
    }

    match fields.algorithm.as_str() {
        ALG_ED25519 => verify_ed25519(message, fields, key_bytes),
        ALG_ES256 => verify_es256(message, fields, key_bytes),
        other => Ok(Verdict::Invalid {
            reason: format!(
                "unsupported algorithm `{other}` (this module verifies {ALG_ED25519}, {ALG_ES256})"
            ),
        }),
    }
}

/// A `sig:signer` pre-check: if the graph names a signer and it differs from `provided`, the
/// signature was made for a DIFFERENT key — a clear verdict (the crypto check would fail too,
/// less legibly). `None` if it matches or is absent.
fn signer_mismatch(fields: &SigFields, provided: &str) -> Option<Verdict> {
    match &fields.signer_b64 {
        Some(embedded) if embedded != provided => Some(Verdict::Invalid {
            reason: format!(
                "provided public key ({provided}) is not the graph's signer ({embedded})"
            ),
        }),
        _ => None,
    }
}

fn verify_ed25519(message: &[u8], fields: &SigFields, key_bytes: &[u8]) -> Result<Verdict, String> {
    let key = parse_ed25519_public(key_bytes)?;
    let provided = ed25519_signer_b64(&key);
    if let Some(v) = signer_mismatch(fields, &provided) {
        return Ok(v);
    }
    let sig_bytes = B64
        .decode(fields.value_b64.as_bytes())
        .map_err(|e| format!("sig:value is not valid base64: {e}"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("sig:value is not a 64-byte Ed25519 signature: {e}"))?;
    // `verify_strict`, not `verify`: a signature is this crate's content-address
    // (`urn:sign:sha256:{sha256(signature)}`), so verification must admit exactly ONE
    // valid signature per (message, key). The permissive `verify` accepts small-order (weak)
    // keys — a hole that lets a forged signature validate almost any message, minting a bogus
    // `urn:sign:` node.
    // `verify_strict` rejects small-order `A`/`R`; S-scalar canonicity is enforced by `from_slice`.
    Ok(match key.verify_strict(message, &signature) {
        Ok(()) => Verdict::Valid {
            algorithm: ALG_ED25519.to_string(),
            signer_b64: provided,
        },
        Err(_) => Verdict::Invalid {
            reason: "signature does not verify against the provided public key".to_string(),
        },
    })
}

fn verify_es256(message: &[u8], fields: &SigFields, key_bytes: &[u8]) -> Result<Verdict, String> {
    let key = parse_p256_public(key_bytes)?;
    let provided = p256_signer_b64(&key)?;
    if let Some(v) = signer_mismatch(fields, &provided) {
        return Ok(v);
    }
    let sig_bytes = B64
        .decode(fields.value_b64.as_bytes())
        .map_err(|e| format!("sig:value is not valid base64: {e}"))?;
    let signature = P256Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("sig:value is not a 64-byte P-256 (ES256) signature: {e}"))?;
    Ok(match key.verify(message, &signature) {
        Ok(()) => Verdict::Valid {
            algorithm: ALG_ES256.to_string(),
            signer_b64: provided,
        },
        Err(_) => Verdict::Invalid {
            reason: "signature does not verify against the provided public key".to_string(),
        },
    })
}

/// The `sig:signer` encoding for a P-256 public key — SPKI DER, base64 — identical to what
/// [`AnySigner::sign`] emits, so the verify-side pre-check compares like for like.
fn p256_signer_b64(key: &P256VerifyingKey) -> Result<String, String> {
    key.to_public_key_der()
        .map(|d| B64.encode(d.as_bytes()))
        .map_err(|e| format!("cannot encode the P-256 public key: {e}"))
}

// =====================================================================================
// The endpoints — the only kernel-aware layer.
// =====================================================================================

/// Mount the module at its conventional IRIs: `urn:sign:sign` (cap-gated) and
/// `urn:sign:verify` (open). A host links this crate and mounts the returned space.
pub fn space() -> EndpointSpace {
    EndpointSpace::new()
        .bind(Exact::new("urn:sign:sign"), Sign)
        .bind(Exact::new("urn:sign:verify"), Verify)
}

/// `urn:sign:sign` — sign `in` bytes with the `key` private key, emitting the RDF
/// signature-graph. The algorithm follows the key (Ed25519 or ES256) and is recorded in
/// `sig:algorithm`; it is never a caller-supplied argument. Requires `urn:cap:sign` —
/// kernel-enforced before dispatch, re-checked at
/// entry (see [`CAP_SIGN`]).
struct Sign;

#[async_trait]
impl Endpoint for Sign {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        // The kernel has already refused a caller without `urn:cap:sign`, before dispatch
        // and before any cache-serve. This entry check is the second line, for the paths
        // where no kernel gate ran — a detached invocation, a module shim. A typed `Denied`
        // (permanent, never transient).
        if !inv.capability.allows(CAP_SIGN) {
            return Err(CoreError::Denied(format!(
                "urn:sign:sign requires the {CAP_SIGN} capability"
            )));
        }

        let message = read_bytes(
            inv,
            &["in", "content"],
            "urn:sign:sign",
            "bytes to sign (`in`)",
        )?;
        let key_repr = resolve_key(inv, "urn:sign:sign").await?;
        let signer = AnySigner::parse(&key_repr.bytes)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:sign: {e}")))?;

        let graph = sign_to_graph(&message, &signer)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:sign: {e}")))?;
        Ok(Representation::new(
            ReprType::new(MEDIA_TURTLE).with_param("charset", "utf-8"),
            graph.into_bytes(),
        )
        // Pure function of (bytes, key). The key was sourced through the kernel via
        // `inv.source`, so its expiry and golden threads fold into this result — the cache
        // clamps to the key's freshness automatically. Deterministic ⇒ safe to cache.
        .cacheable())
    }

    fn name(&self) -> &str {
        "sign"
    }

    fn describe(&self) -> Description {
        Description::new("sign")
            .title("Sign (RDF signature-graph, Ed25519 or ES256)")
            .summary(
                "Sign bytes with a kernel-resolved PKCS8 private key, emitting a DETERMINISTIC \
                 RDF signature-graph (text/turtle): a sig:Signature with sig:algorithm, \
                 sig:signer (base64 pubkey), sig:value (base64 signature), and sig:contentHash \
                 (the digest, TAGGED with its algorithm: sha256:<hex>). The algorithm follows \
                 the key — Ed25519 or ES256 (ECDSA P-256, the Secure-Enclave/TPM algorithm). \
                 Pass the bytes as `in` (or pipe them as `content`) and the private-key \
                 resource URI as `key=` (urn:/file: — resolved \
                 THROUGH the kernel, cap-scoped). No timestamp, so the graph is content-\
                 addressable; the node IRI is skolemized and tagged with the digest that \
                 addressed it (urn:sign:sha256:<hex>), no blank nodes. \
                 Requires the urn:cap:sign capability.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .requires(CAP_SIGN)
            // `xsd:string` is the WIRE's type, not the value's: `in` is opaque bytes (a PDF
            // is valid input) and no XSD datatype is true of them, but a piped value and an
            // MCP argument both arrive as a string, and that is what an agent forming the
            // call needs to know.
            .input(
                ArgSpec::new("in")
                    .summary("the bytes to sign (positional/named, or piped as `content`)")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("content")
                    .summary("the bytes to sign — the piped-in alternative to `in`")
                    .class(XSD_STRING)
                    .optional(),
            )
            .input(
                ArgSpec::new("key")
                    .summary(
                        "URI of the PKCS8 PRIVATE key resource (PEM or DER) — Ed25519 or P-256 \
                         (ES256), discovered from the key — resolved through the kernel, e.g. \
                         urn:file:my.pem or urn:secret:…",
                    )
                    .class(RDFS_RESOURCE),
            )
            .output(MEDIA_TURTLE)
    }
}

/// `urn:sign:verify` — verify `in` bytes against a `sig` signature-graph using the `key` public
/// key. Open (no capability); verification is public.
struct Verify;

#[async_trait]
impl Endpoint for Verify {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        let message = read_bytes(inv, &["in"], "urn:sign:verify", "bytes to verify (`in`)")?;
        let sig_turtle = read_str(
            inv,
            &["sig", "content"],
            "urn:sign:verify",
            "signature-graph (`sig`, or piped `content`)",
        )?;
        let fields = parse_sig_graph(sig_turtle)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:verify: {e}")))?;

        let key_repr = resolve_key(inv, "urn:sign:verify").await?;
        let verdict = verify_message(&message, &fields, &key_repr.bytes)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:verify: {e}")))?;

        Ok(Representation::new(
            ReprType::new(MEDIA_PLAIN).with_param("charset", "utf-8"),
            verdict.render().into_bytes(),
        )
        // Pure function of (bytes, sig-graph, key); the key folds in its freshness via
        // `inv.source`. Deterministic ⇒ cacheable.
        .cacheable())
    }

    fn name(&self) -> &str {
        "verify"
    }

    fn describe(&self) -> Description {
        Description::new("verify")
            .title("Verify (RDF signature-graph, Ed25519 or ES256)")
            .summary(
                "Verify bytes against an RDF signature-graph with a kernel-resolved SPKI public \
                 key. Pass the bytes as `in`, the signature-graph as `sig` (or pipe it as \
                 `content`), and the public-key resource URI as `key=` (resolved through the \
                 kernel). It parses the graph, recomputes the content hash and compares it to \
                 the graph's sig:contentHash (sha256:<hex>; an untagged hex digest is read as \
                 SHA-256 for pre-0.2 graphs, any other tag is refused), and — \
                 dispatching on the graph's sig:algorithm — Ed25519- or ES256-verifies the \
                 signature against the public key (parsed as that algorithm). Output is \
                 text/plain — `valid: signed by …` or `invalid: <reason>`. A signature that \
                 doesn't check out is a normal `invalid` answer, not an error; only a malformed \
                 graph/key is an error. Open — no capability required.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("in")
                    .summary("the bytes to verify")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("sig")
                    .summary("the RDF signature-graph (Turtle), named or piped as `content`")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("content")
                    .summary("the signature-graph — the piped-in alternative to `sig`")
                    .class(XSD_STRING)
                    .optional(),
            )
            .input(
                ArgSpec::new("key")
                    .summary(
                        "URI of the SPKI PUBLIC key resource (PEM or DER) of the graph's \
                         sig:algorithm — Ed25519 or P-256 (ES256) — resolved through the kernel",
                    )
                    .class(RDFS_RESOURCE),
            )
            .output(MEDIA_PLAIN)
    }
}

// =====================================================================================
// Kernel-aware input helpers.
// =====================================================================================

/// Read the first present inline argument among `names` as raw bytes. `iri`/`what` frame the
/// "no input" error.
fn read_bytes(inv: &Invocation<'_>, names: &[&str], iri: &str, what: &str) -> CoreResult<Vec<u8>> {
    for name in names {
        if let Ok(bytes) = inv.inline_arg(name) {
            return Ok(bytes.to_vec());
        }
    }
    Err(CoreError::Endpoint(format!(
        "{iri} needs the {what} — pass {} or pipe it in",
        names
            .iter()
            .map(|n| format!("`{n}=`"))
            .collect::<Vec<_>>()
            .join(" / ")
    )))
}

/// Read the first present inline argument among `names` as a UTF-8 string.
fn read_str<'a>(
    inv: &'a Invocation<'_>,
    names: &[&str],
    iri: &str,
    what: &str,
) -> CoreResult<&'a str> {
    for name in names {
        if let Ok(s) = inv.inline_str(name) {
            return Ok(s);
        }
    }
    Err(CoreError::Endpoint(format!(
        "{iri} needs the {what} — pass {} or pipe it in",
        names
            .iter()
            .map(|n| format!("`{n}=`"))
            .collect::<Vec<_>>()
            .join(" / ")
    )))
}

/// Resolve the `key` argument — a resource **URI** — THROUGH the kernel, recording it as a
/// dependency (so a cached result invalidates when the key changes). The value arrives inline
/// as an IRI string (the engine passes `key=urn:…` inline); http(s) is not a key transport, so
/// only `urn:`/`file:` resolvable IRIs are accepted. Errors if detached (no kernel context).
async fn resolve_key(inv: &Invocation<'_>, iri: &str) -> CoreResult<Representation> {
    let key_uri = inv.inline_str("key").map_err(|_| {
        CoreError::Endpoint(format!(
            "{iri} needs `key=<uri>` — the URI of the key resource, resolved through the kernel"
        ))
    })?;
    let key_iri = Iri::parse(key_uri)
        .map_err(|e| CoreError::Endpoint(format!("{iri}: bad key IRI `{key_uri}`: {e}")))?;
    inv.issue(Request::new(Verb::Source, key_iri)).await
}

#[cfg(test)]
mod tests;
