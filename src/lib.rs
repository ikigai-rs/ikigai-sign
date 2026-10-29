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
//!    PKCS8 (or, for P-256, SEC1) **private** key resource — Ed25519 **or** P-256; the
//!    algorithm is discovered from
//!    the key, never stated by the caller. The key is dereferenced **through the kernel**
//!    (`inv.source` on the URI, cap-scoped) — so `key=urn:file:my.pem` works today and
//!    `key=urn:secret:…` works unchanged the moment a secrets backend exists. Only `urn:` and
//!    `file:` key IRIs are accepted (a typed `InvalidArgument` otherwise). Output is a
//!    **deterministic** RDF signature-graph (`text/turtle`): a `sig:Signature` with
//!    `sig:algorithm`, `sig:signer` (base64 public key), `sig:value` (base64 signature), and
//!    `sig:contentHash` (**`sha256:<hex>`** — the digest names its algorithm, see
//!    [`HASH_ALG_SHA256`]). No timestamp — both algorithms sign deterministically (Ed25519 by
//!    construction, ES256 via RFC 6979, emitted in its low-S form), so the same
//!    `(bytes, key)` yields byte-identical Turtle, and the graph is
//!    content-addressable/cacheable. The signature node is **skolemized** to a stable IRI
//!    content-addressed on the signature and **tagged with the digest algorithm that
//!    addressed it** — `urn:sign:sha256:<hex>` (see [`HASH_ALG_SHA256`]); no blank nodes.
//!
//! 2. **`urn:sign:verify`** (Source, **open** — no capability) — verify bytes against a
//!    signature-graph. Inputs: `in` = the bytes, `sig` = the signature-graph (piped `content`
//!    fallback), `key` = the URI of a SPKI **public** key resource — Ed25519 or P-256, matching
//!    the graph's `sig:algorithm` (kernel-resolved).
//!    It parses the graph — exactly one `sig:Signature` node, its fields read from that node
//!    only — recomputes the content hash of `in` and compares it to the graph's
//!    `sig:contentHash` (an UNTAGGED digest is read as SHA-256, so records signed before the
//!    tag existed still verify; an unrecognised tag is refused, never assumed), then
//!    **dispatches on the graph's `sig:algorithm`** and verifies with that algorithm against the
//!    public key — strictly: Ed25519 via `verify_strict`, ES256 low-S only, so exactly one
//!    signature per (message, key) is ever `valid`. Output is `text/plain`: a clear `valid` / `invalid`
//!    verdict. A signature that simply does not check out is **not an error** — it is a `valid:
//!    …` / `invalid: …` answer (`Ok`); only a malformed or ambiguous graph / unreadable key / missing field
//!    is an `Err`. Never panics on hostile input. **The node's IRI is never read** — see
//!    the private `parse_sig_graph` — so a graph minted under either spelling of the name verifies the
//!    same way, and the tagging of the identifier in 0.2.1 was a discontinuity in a naming
//!    scheme, not a migration.
//!
//! On both endpoints a required input left out is core's typed `MissingArgument` naming it
//! (`in`, `sig`, `key`; a piped `content` stands in for `in` on `sign` and for `sig` on
//! `verify`). On the bytes path (`invoke`) one given but not an inline value is
//! `InvalidArgument` naming it.
//!
//! ## Streamed messages (since 0.4.1)
//!
//! The kernel calls `invoke_body`, and there both endpoints read the message — `in`, or the
//! piped `content` — as a **body**, in any of its forms (inline, by reference, by content id),
//! hashing and signing or verifying it **as it is read, never holding it whole**, so a message
//! far larger than the run's byte budget signs and verifies. The answer is byte-identical to
//! the bytes path's. How often the message is read depends on the algorithm:
//!
//! - **Ed25519 signing reads it twice** (RFC 8032 without prehash hashes the message once
//!   for the nonce and again for the challenge), so it takes a body that can be read again
//!   (`Bytes`, `Replay`) and refuses a one-shot (`Once`) body with `InvalidArgument` naming
//!   the argument and `urn:stream:spill`, the builtin that makes it re-readable. It never
//!   spills on its own. If the two reads differ, the answer is `Conflict`, not a signature.
//! - **ES256 signing reads it once**, and so does **verification** of either algorithm. A
//!   `sig:contentHash` under an unknown digest tag is refused without reading it at all.
//!
//! The signature-graph `verify` parses is held whole, so it is collected under the run's byte
//! budget (`urn:cap:stream:memory:<bytes>`): past it the answer is `OverBudget`. A message
//! stream that fails part-way ends the answer with its error, never a signature or verdict
//! over the bytes before it. Both actions declare their failure classes: `over-budget` and
//! `unknown` (a malformed key or graph), with `permanent` implied.
//!
//! ## Keys
//!
//! Standard **PKCS8** (private) and **SPKI** (public) keys, in PEM or DER, of either supported
//! algorithm — exactly what `openssl genpkey -algorithm ed25519` and `openssl genpkey
//! -algorithm EC -pkeyopt ec_paramgen_curve:P-256` emit, and what a `urn:secret:*` custody
//! backend will serve. A P-256 private key is also accepted in **SEC1** (`EC PRIVATE KEY`, PEM
//! or DER, with or without a leading `EC PARAMETERS` block), which is what `openssl ecparam
//! -name prime256v1 -genkey` writes; its curve is checked, not assumed. The caller
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
//! Defined in [`VOCABULARY_TTL`] under `https://ikigai-rs.dev/ns/sign#` (see [`SIG_NS`]).
//! The vocabulary is published separately from ikigai-vocab at
//! <https://ikigai-rs.dev/ns/sign>; deployment to that URL is manual after publishing
//! this crate. Conformance checks emitted terms against this document.
//!
//! **A second producer exists** as of 2026-08-23: `ikigai-log`'s `#seal` lines carry
//! `sig:contentHash` / `sig:value` rather than minting parallel terms. That is exactly why the
//! digest here is tagged (`sha256:<hex>`) — sharing a predicate while writing two lexical forms
//! of the same value means the two never join in a query, which is a silent failure, not a
//! loud one.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use base64::Engine as _;
use ed25519_dalek::hazmat::{raw_sign_byupdate, ExpandedSecretKey};
use ed25519_dalek::pkcs8::{spki::DecodePublicKey, DecodePrivateKey};
use ed25519_dalek::{Signature, SigningKey, StreamVerifier, VerifyingKey};
use futures_util::StreamExt;
// The `signature` crate's traits, implemented by BOTH algorithms' keys — imported once and
// used for Ed25519 and ES256 alike (this is the crypto-agility, at the trait level).
use ikigai_core::{
    space_iri, ArgSpec, Body, Bytes, Description, Endpoint, EndpointSpace, Error as CoreError,
    Exact, FailureClass, Invocation, Iri, Replay, ReprType, Representation, Request,
    Result as CoreResult, Verb,
};
use oxrdf::Term;
use oxrdfio::{RdfFormat, RdfParser};
use p256::ecdsa::signature::{DigestSigner, DigestVerifier, Signer, Verifier};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256, Sha512};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The capability gating "may sign at all." Declared on `urn:sign:sign` via
/// [`Description::requires`], and so enforced by the kernel *before dispatch* (core 0.1.49
/// onward: declared = enforced is the kernel's baseline, on the same predicate selection and
/// `urn:kernel:validate` use). The endpoint re-checks it at entry as a second line — that
/// check earns its keep only where no kernel gate ran, on a detached invocation or a module
/// shim, and it costs one string comparison.
pub const CAP_SIGN: &str = "urn:cap:sign";

/// The signature vocabulary as Turtle, deployed manually to <https://ikigai-rs.dev/ns/sign>.
///
/// ```
/// assert!(ikigai_sign::VOCABULARY_TTL.contains("owl:Ontology"));
/// ```
pub const VOCABULARY_TTL: &str = include_str!("vocabulary.ttl");

/// The signature vocabulary namespace, defined in [`VOCABULARY_TTL`].
///
/// ```
/// assert_eq!(ikigai_sign::SIG_NS, "https://ikigai-rs.dev/ns/sign#");
/// ```
pub const SIG_NS: &str = "https://ikigai-rs.dev/ns/sign#";

/// `sig:Signature` — the class of the signature node.
///
/// ```
/// assert_eq!(ikigai_sign::SIG_SIGNATURE, "https://ikigai-rs.dev/ns/sign#Signature");
/// ```
pub const SIG_SIGNATURE: &str = "https://ikigai-rs.dev/ns/sign#Signature";
/// `sig:algorithm` — the signature algorithm id: `Ed25519` or `ES256`, chosen by
/// the key the signer was parsed from. **Not a constant.** It was `Ed25519` for every graph
/// this module emitted before 0.2.0; since 0.2.0 `urn:sign:sign` dispatches on key type and
/// verification dispatches on this literal, so a consumer branching on it has two arms to
/// write and a third to refuse. (Refuse, do not assume: an unknown algorithm read as Ed25519
/// would mint a confident verdict on a check that never happened — the same reasoning as
/// the content hash reader's unknown-tag arm.)
///
/// ```
/// assert_eq!(ikigai_sign::SIG_ALGORITHM, "https://ikigai-rs.dev/ns/sign#algorithm");
/// ```
pub const SIG_ALGORITHM: &str = "https://ikigai-rs.dev/ns/sign#algorithm";
/// `sig:signer` — the base64-encoded public key of the signer, **in this algorithm's own
/// encoding**: a raw 32-byte key for `Ed25519`, an SPKI DER document for `ES256`. The two are
/// not interchangeable and the length does not identify them — read `sig:algorithm` first.
///
/// ```
/// assert_eq!(ikigai_sign::SIG_SIGNER, "https://ikigai-rs.dev/ns/sign#signer");
/// ```
pub const SIG_SIGNER: &str = "https://ikigai-rs.dev/ns/sign#signer";
/// `sig:value` — the base64-encoded 64-byte signature: Ed25519's `R‖S`, or ES256's `r‖s`
/// (fixed-width, not DER — the Enclave's DER output is converted at the sign-through
/// boundary), with ES256's `s` always in the LOW half of the group order: `urn:sign:sign` emits
/// low-S and `urn:sign:verify` refuses high-S (since 0.2.3). Same width for both algorithms,
/// so the width proves nothing about which.
///
/// ```
/// assert_eq!(ikigai_sign::SIG_VALUE, "https://ikigai-rs.dev/ns/sign#value");
/// ```
pub const SIG_VALUE: &str = "https://ikigai-rs.dev/ns/sign#value";
/// `sig:contentHash` — the **algorithm-tagged** digest of the signed bytes: `sha256:<hex>`.
///
/// ```
/// assert_eq!(ikigai_sign::SIG_CONTENT_HASH, "https://ikigai-rs.dev/ns/sign#contentHash");
/// ```
pub const SIG_CONTENT_HASH: &str = "https://ikigai-rs.dev/ns/sign#contentHash";

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
    ///
    /// A P-256 key is ALSO accepted in SEC1 (`-----BEGIN EC PRIVATE KEY-----`, or its DER), with
    /// or without the `EC PARAMETERS` block in front — exactly what `openssl ecparam -name
    /// prime256v1 -genkey` writes, which this crate's documentation has long named as a usable
    /// recipe (it was not, until ledger #857). See [`parse_p256_sec1`].
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
        let pkcs8_err = match ec {
            Ok(k) => return Ok(AnySigner::Es256(Box::new(k))),
            Err(e) => e,
        };
        // SEC1, but only for input that IS SEC1-shaped — so a SEC1 key that fails says why
        // (wrong curve, malformed), and anything else keeps the PKCS8 message it always had.
        let sec1_shaped = match as_pem(bytes) {
            Some(pem) => pem.contains("-----BEGIN EC "),
            None => sec1::EcPrivateKey::try_from(bytes).is_ok(),
        };
        if sec1_shaped {
            return parse_p256_sec1(bytes)
                .map(|k| AnySigner::Es256(Box::new(k)))
                .map_err(|e| format!("not a usable SEC1 P-256 (ES256) private key: {e}"));
        }
        Err(format!(
            "not a PKCS8 Ed25519, PKCS8 P-256 or SEC1 P-256 (ES256) private key \
             (P-256 PKCS8 parse: {pkcs8_err})"
        ))
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
            AnySigner::Es256(k) => es256_encode(k, k.sign(message)),
        }
    }
}

/// An ES256 signature and its signer in the wire encoding: `(base64 r‖s, base64 SPKI DER)`.
/// Shared by the bytes path and the body path, so the two emit the same literals.
fn es256_encode(k: &P256SigningKey, sig: P256Signature) -> Result<(String, String), String> {
    // Emit LOW-S. RFC 6979 fixes the nonce, not which of the two valid `s` values comes out,
    // and p256 does not normalize — so about half of raw signatures are high-S, and
    // `verify_es256` refuses those (one valid signature per (message, key), or the
    // content-addressed node name is forgeable). Still deterministic: normalization is a pure
    // function of the signature.
    let sig = sig.normalize_s().unwrap_or(sig);
    let spki = k
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| format!("cannot encode the P-256 public key: {e}"))?;
    Ok((B64.encode(sig.to_bytes()), B64.encode(spki.as_bytes())))
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

/// The named-curve OID for NIST P-256 (`prime256v1` / `secp256r1`).
const P256_OID: sec1::der::asn1::ObjectIdentifier =
    sec1::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// Parse a SEC1 P-256 private key — PEM (`EC PRIVATE KEY`, optionally preceded by `EC
/// PARAMETERS`, as `openssl ecparam -genkey` writes it) or DER.
///
/// **The curve is checked, because p256's own SEC1 loader does not**: it reads the 32-byte
/// scalar and validates the embedded public key if there is one, but never reads the key's
/// curve parameter (an upstream TODO). A 32-byte secp256k1 scalar with no public half would
/// otherwise load as a P-256 key and sign under a curve its owner never chose. So: the
/// `EC PARAMETERS` block, if present, must name P-256; the key's own `[0]` parameter, if
/// present, must name P-256; and a key with NEITHER that parameter NOR a public half (which
/// p256 checks against the scalar) names no curve at all and is refused.
fn parse_p256_sec1(bytes: &[u8]) -> Result<P256SigningKey, String> {
    use sec1::der::Decode;

    let der = match as_pem(bytes) {
        Some(pem) => {
            let mut key: Option<Vec<u8>> = None;
            for (label, der) in pem_blocks(pem)? {
                match label.as_str() {
                    "EC PARAMETERS" => {
                        let params = sec1::EcParameters::from_der(&der)
                            .map_err(|e| format!("unreadable `EC PARAMETERS` block: {e}"))?;
                        match params.named_curve() {
                            Some(oid) if oid == P256_OID => {}
                            Some(oid) => {
                                return Err(format!(
                                    "the `EC PARAMETERS` block names curve {oid}, which is not \
                                     P-256 (prime256v1, {P256_OID})"
                                ))
                            }
                            None => return Err("the `EC PARAMETERS` block names no curve".into()),
                        }
                    }
                    "EC PRIVATE KEY" if key.is_none() => key = Some(der),
                    "EC PRIVATE KEY" => return Err("more than one `EC PRIVATE KEY` block".into()),
                    other => {
                        return Err(format!(
                            "unexpected PEM block `{other}` beside a SEC1 key (expected only \
                             `EC PARAMETERS` and one `EC PRIVATE KEY`)"
                        ))
                    }
                }
            }
            key.ok_or("no `EC PRIVATE KEY` block")?
        }
        None => bytes.to_vec(),
    };

    let ec = sec1::EcPrivateKey::try_from(der.as_slice())
        .map_err(|e| format!("not a SEC1 ECPrivateKey: {e}"))?;
    match ec.parameters.and_then(|p| p.named_curve()) {
        Some(oid) if oid == P256_OID => {}
        Some(oid) => {
            return Err(format!(
                "the key names curve {oid}, which is not P-256 (prime256v1, {P256_OID})"
            ))
        }
        None if ec.public_key.is_none() => {
            return Err(
                "the key names no curve and carries no public key, so nothing says it is P-256"
                    .into(),
            )
        }
        None => {}
    }
    let secret = p256::SecretKey::try_from(ec)
        .map_err(|e| format!("not a valid P-256 key (scalar or public half rejected): {e}"))?;
    Ok(P256SigningKey::from(secret))
}

/// Split PEM text into its `(label, DER)` blocks, in order. Strict: anything outside the
/// armor other than whitespace is refused, so a block cannot hide behind prose.
fn pem_blocks(pem: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut blocks = Vec::new();
    let mut rest = pem;
    loop {
        let trimmed = rest.trim_start();
        if trimmed.is_empty() {
            return Ok(blocks);
        }
        let header = trimmed
            .strip_prefix("-----BEGIN ")
            .ok_or("text outside a PEM block")?;
        let label = &header[..header.find("-----").ok_or("unterminated PEM header")?];
        let end_line = format!("-----END {label}-----");
        let end = trimmed
            .find(&end_line)
            .ok_or_else(|| format!("no `{end_line}` line"))?
            + end_line.len();
        let (_, der) = sec1::der::pem::decode_vec(&trimmed.as_bytes()[..end])
            .map_err(|e| format!("malformed `{label}` PEM block: {e}"))?;
        blocks.push((label.to_string(), der));
        rest = &trimmed[end..];
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
    Ok(render_graph(
        signer.algorithm(),
        &sig_b64,
        &signer_b64,
        &tagged_content_hash(message),
    ))
}

/// The signature-graph for an already-made signature: the one renderer behind both the bytes
/// path ([`sign_to_graph`]) and the body path ([`sign_body`]), so the two cannot drift apart.
fn render_graph(algorithm: &str, sig_b64: &str, signer_b64: &str, content_hash: &str) -> String {
    // Skolemize: the node IRI is content-addressed on the (deterministic) signature bytes, so
    // the graph is stable and diffable and carries no blank node. WHAT it is derived from —
    // sha256 over the BASE64 TEXT of the signature — is load-bearing (see `verify_ed25519` and
    // `verify_es256`: verification must admit exactly one valid signature per (message, key),
    // or this name is forgeable — ES256 only since 0.2.3, ledger #857), and the tag does not
    // touch it: 0.2.1 added an algorithm label to the name,
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
        turtle_string(signer_b64)
    ));
    out.push_str(&format!(
        "<{node}> sig:value {} .\n",
        turtle_string(sig_b64)
    ));
    out.push_str(&format!(
        "<{node}> sig:contentHash {} .\n",
        turtle_string(content_hash)
    ));
    out
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

/// The four `sig:` field predicates, with the short names errors use.
const SIG_FIELDS: [(&str, &str); 4] = [
    (SIG_ALGORITHM, "sig:algorithm"),
    (SIG_VALUE, "sig:value"),
    (SIG_CONTENT_HASH, "sig:contentHash"),
    (SIG_SIGNER, "sig:signer"),
];

/// What one subject of a signature-graph says, as far as verification cares.
#[derive(Default)]
struct SigNode {
    /// `rdf:type sig:Signature`.
    typed: bool,
    /// Field short name (`sig:value`, …) → its distinct literal values. A SET, because RDF is
    /// one: the same triple written twice is one triple, not a conflict.
    fields: BTreeMap<&'static str, BTreeSet<String>>,
}

/// Parse a signature-graph (Turtle) into its [`SigFields`]: the literals of its ONE
/// `sig:Signature` node, and only that node's. Any parse failure, missing required field or
/// ambiguity is a clear `Err`; never panics.
///
/// Read **per subject** (ledger #857). Until 0.2.3 the fields were collected predicate by
/// predicate across every subject, so a graph holding two signatures — two parties' graphs
/// concatenated, or `urn:rdf:union`ed — gave a verdict that depended on triple order, and the
/// fields need not have belonged to the signature node at all. Now each of these is refused,
/// by name: no `sig:Signature` node, more than one, a `sig:` field on any OTHER subject, a
/// field with two different values, a field whose object is not a literal. Triples that use
/// no `sig:` field predicate are left alone — a signature-graph may sit beside a description
/// of what it signs. These are SHAPE refusals (`Err`), like a missing field always was: there
/// is no single signature to give a verdict on.
///
/// **The subject IRI is still never read** — which subject is the signature is decided by its
/// `rdf:type`, never by its name. The node's name is an output of signing, not an input to
/// verification, so a graph minted before the name carried its digest tag (`urn:sign:<hex>`)
/// verifies exactly like one minted after it (`urn:sign:sha256:<hex>`), and so does a node
/// named anything else; there is nothing to migrate and nothing joins the forms.
fn parse_sig_graph(turtle: &str) -> Result<SigFields, String> {
    // Keyed by the subject's N-Triples form, ordered so every message is deterministic.
    let mut nodes: BTreeMap<String, SigNode> = BTreeMap::new();

    for quad in RdfParser::from_format(RdfFormat::Turtle).for_slice(turtle.as_bytes()) {
        let quad = quad.map_err(|e| format!("signature-graph parse error: {e}"))?;
        let predicate = quad.predicate.as_str();
        if predicate == RDF_TYPE {
            if matches!(&quad.object, Term::NamedNode(n) if n.as_str() == SIG_SIGNATURE) {
                nodes.entry(quad.subject.to_string()).or_default().typed = true;
            }
            continue;
        }
        let Some(&(_, name)) = SIG_FIELDS.iter().find(|(iri, _)| *iri == predicate) else {
            continue;
        };
        let Term::Literal(literal) = &quad.object else {
            return Err(format!(
                "{name} on {} is not a literal ({})",
                quad.subject, quad.object
            ));
        };
        nodes
            .entry(quad.subject.to_string())
            .or_default()
            .fields
            .entry(name)
            .or_default()
            .insert(literal.value().to_string());
    }

    let typed: Vec<&String> = nodes
        .iter()
        .filter(|(_, n)| n.typed)
        .map(|(s, _)| s)
        .collect();
    let subject = match typed.as_slice() {
        [] => {
            return Err(format!(
                "no `sig:Signature` (`<{SIG_SIGNATURE}>`) node in the signature-graph"
            ))
        }
        [one] => (*one).clone(),
        many => {
            return Err(format!(
                "the signature-graph holds {} `sig:Signature` nodes ({}); verification reads \
                 exactly one, so verify each signature against a graph of its own",
                many.len(),
                many.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
    };
    if let Some((stray, node)) = nodes
        .iter()
        .find(|(s, n)| **s != subject && !n.fields.is_empty())
    {
        return Err(format!(
            "{} on {stray}, which is not the graph's `sig:Signature` node ({subject}); a \
             signature-graph's `sig:` fields all describe its one signature",
            node.fields.keys().copied().collect::<Vec<_>>().join(", ")
        ));
    }

    let mut node = nodes.remove(&subject).unwrap_or_default();
    let mut take = |name: &str| -> Result<Option<String>, String> {
        let values = node.fields.remove(name).unwrap_or_default();
        if values.len() > 1 {
            return Err(format!(
                "the `sig:Signature` node {subject} carries {} different {name} values",
                values.len()
            ));
        }
        Ok(values.into_iter().next())
    };
    Ok(SigFields {
        algorithm: take("sig:algorithm")?.ok_or("signature-graph missing sig:algorithm")?,
        value_b64: take("sig:value")?.ok_or("signature-graph missing sig:value")?,
        content_hash: take("sig:contentHash")?.ok_or("signature-graph missing sig:contentHash")?,
        signer_b64: take("sig:signer")?,
    })
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
        Err(tag) => return Ok(unsupported_hash_verdict(tag)),
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
        other => Ok(unsupported_algorithm_verdict(other)),
    }
}

/// The verdict on a `sig:contentHash` whose digest tag this module does not compute.
fn unsupported_hash_verdict(tag: &str) -> Verdict {
    Verdict::Invalid {
        reason: format!(
            "unsupported content-hash algorithm `{tag}` in sig:contentHash (this module \
             computes {HASH_ALG_SHA256}); refusing to assume it is {HASH_ALG_SHA256}"
        ),
    }
}

/// The verdict on a `sig:algorithm` this module does not verify.
fn unsupported_algorithm_verdict(algorithm: &str) -> Verdict {
    Verdict::Invalid {
        reason: format!(
            "unsupported algorithm `{algorithm}` (this module verifies {ALG_ED25519}, {ALG_ES256})"
        ),
    }
}

/// The verdict on a high-S ES256 signature (see [`verify_es256`]).
fn high_s_verdict() -> Verdict {
    Verdict::Invalid {
        reason: "high-S ES256 signature: s is in the upper half of the group order, the \
                 non-canonical twin of a low-S signature; this module admits exactly one valid \
                 signature per (message, key) and accepts only the low-S form"
            .to_string(),
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
            reason: DOES_NOT_VERIFY.to_string(),
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
    // LOW-S only — ES256's `verify_strict`. ECDSA is malleable: if `(r, s)` verifies, so does
    // `(r, n − s)`, and anyone can compute that twin from a published graph WITHOUT the key.
    // A signature is this crate's content-address, so admitting both would let a stranger mint
    // a second `urn:sign:` node for a fact signed once (ledger #857; both auditors reproduced
    // it). `urn:sign:sign` emits low-S, so this refuses only signatures this module would
    // never have produced. A verdict, not an error: the graph is well-formed, it just does not
    // carry the one signature this module accepts.
    if signature.normalize_s().is_some() {
        return Ok(high_s_verdict());
    }
    Ok(match key.verify(message, &signature) {
        Ok(()) => Verdict::Valid {
            algorithm: ALG_ES256.to_string(),
            signer_b64: provided,
        },
        Err(_) => Verdict::Invalid {
            reason: DOES_NOT_VERIFY.to_string(),
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
// The body path (ledger #2285): the same sign and verify over a message that arrives as a
// streamed body — hashed as it is read, never held whole. Kernel-free like the core above;
// `Sign::invoke_body` and `Verify::invoke_body` are its only callers.
//
// How many passes each operation makes over the message, and so which bodies it takes:
//
// | operation       | passes | `Bytes` | `Replay`        | `Once`                         |
// |-----------------|--------|---------|-----------------|--------------------------------|
// | Ed25519 sign    | 2      | yes     | opened twice    | refused: `InvalidArgument`     |
// | ES256 sign      | 1      | yes     | opened once     | read once                      |
// | verify (either) | 1      | yes     | opened once     | read once                      |
//
// Ed25519 (RFC 8032, without prehash) hashes the message twice while signing: once for the
// nonce `r`, once for the challenge `k`, which needs `R = rB` from the first. A one-shot body
// cannot be read a second time, so it is refused with a pointer to `urn:stream:spill`, which
// turns it into a body that can; sign never spills on its own (a spill writes to the host's
// disk under the CALLER's disk budget, which is the caller's to spend). Ed25519ph would sign
// in one pass, but it is a different algorithm with different signatures, and `sig:value`
// stays what it always was. ES256 hashes once (SHA-256, which is also `sig:contentHash`), and
// verification of either algorithm is one pass.
// =====================================================================================

/// A message body that can be read again: what Ed25519 signing needs. A `Once` body has no
/// such form; [`Rereadable::of`] says so.
enum Rereadable {
    Bytes(Bytes),
    Replay(Arc<dyn Replay>),
}

impl Rereadable {
    /// The body, if it can be read again; a one-shot body is handed back untouched.
    fn of(body: Body) -> Result<Rereadable, Body> {
        match body {
            Body::Bytes(bytes) => Ok(Rereadable::Bytes(bytes)),
            Body::Replay(replay) => Ok(Rereadable::Replay(replay)),
            once @ Body::Once(_) => Err(once),
        }
    }

    /// A fresh read from the first byte.
    fn open(&self) -> Body {
        match self {
            Rereadable::Bytes(bytes) => Body::Bytes(bytes.clone()),
            Rereadable::Replay(replay) => Body::Replay(Arc::clone(replay)),
        }
    }
}

/// Read `body` once, start to end, handing each chunk to `each` and holding none of them.
/// A stream that fails part-way ends the read with ITS error — a reader never takes the chunks
/// before an error item as the whole message (refuse, never truncate).
async fn read_pass(body: Body, mut each: impl FnMut(&[u8])) -> CoreResult<()> {
    let mut stream = body.into_stream();
    while let Some(chunk) = stream.next().await {
        each(&chunk?);
    }
    Ok(())
}

/// Sign a streamed message: the body-path twin of [`sign_to_graph`], byte-identical to it for
/// the same `(message, key)`. `arg` names the argument the message came in, for the refusal.
///
/// Ed25519 reads a re-readable message twice and refuses a one-shot one; ES256 reads once.
async fn sign_body(message: Body, arg: &str, signer: &AnySigner) -> CoreResult<String> {
    let fail = |e: String| CoreError::Endpoint(format!("urn:sign:sign: {e}"));
    match signer {
        AnySigner::Ed25519(key) => {
            let message = Rereadable::of(message).map_err(|_| CoreError::InvalidArgument {
                name: arg.to_string(),
                detail: format!(
                    "urn:sign:sign: an {ALG_ED25519} key signs in two passes over the message, \
                     and `{arg}` is a one-shot stream that can be read only once; make it \
                     re-readable first with `{}` (or sign with an {ALG_ES256} key, which reads \
                     once)",
                    ikigai_core::stream::SPILL
                ),
            })?;
            let (sig, content_hash) = sign_ed25519_passes(&message, key).await?;
            Ok(render_graph(
                ALG_ED25519,
                &B64.encode(sig.to_bytes()),
                &B64.encode(key.verifying_key().to_bytes()),
                &content_hash,
            ))
        }
        AnySigner::Es256(key) => {
            let mut digest = Sha256::new();
            read_pass(message, |chunk| digest.update(chunk)).await?;
            let content_hash = format!("{HASH_ALG_SHA256}:{}", to_hex(&digest.clone().finalize()));
            let sig: P256Signature = key.sign_digest(digest);
            let (sig_b64, signer_b64) = es256_encode(key, sig).map_err(fail)?;
            Ok(render_graph(
                ALG_ES256,
                &sig_b64,
                &signer_b64,
                &content_hash,
            ))
        }
    }
}

/// Ed25519 over a message read twice, with ed25519-dalek's own signing
/// ([`raw_sign_byupdate`]): the library computes `r`, `R`, `k` and `s`; this function only
/// supplies the two message hashes it asks for.
///
/// `raw_sign_byupdate` asks for the message through a SYNCHRONOUS callback, called twice,
/// and a body is read asynchronously. So each hash is computed here, in its own pass, and the
/// callback hands the library the finished hasher state — the state it would have reached
/// hashing the message itself:
///
/// 1. pass 1 hashes `prefix ‖ M` (the nonce hash, seeded as the library seeds it) and the
///    content hash;
/// 2. a first library call takes that state, derives `R`, seeds the challenge hash with
///    `R ‖ A`, and this callback captures that seeded state and stops the call;
/// 3. pass 2 hashes `M` into the captured state (and the content hash again);
/// 4. a second library call takes both finished states and signs. Signing is deterministic,
///    so its `R` is the one step 2 seeded.
///
/// The two passes must read the same bytes, or the signature is over neither: a
/// [`Replay`] promises it, and this checks it — the content hash of each pass is compared,
/// and a mismatch is a [`CoreError::Conflict`], never a signature.
async fn sign_ed25519_passes(
    message: &Rereadable,
    key: &SigningKey,
) -> CoreResult<(Signature, String)> {
    let expanded = ExpandedSecretKey::from(&key.to_bytes());
    let verifying = key.verifying_key();
    let fail = |e: ed25519_dalek::SignatureError| {
        CoreError::Endpoint(format!("urn:sign:sign: Ed25519 signing failed: {e}"))
    };

    // Pass 1: the nonce hash and the content hash.
    let mut nonce = Sha512::new_with_prefix(expanded.hash_prefix);
    let mut first = Sha256::new();
    read_pass(message.open(), |chunk| {
        nonce.update(chunk);
        first.update(chunk);
    })
    .await?;

    // Learn the challenge hash's seed (`R ‖ A`), then stop the call.
    let seeded: RefCell<Option<Sha512>> = RefCell::new(None);
    let calls = Cell::new(0u8);
    let probe = raw_sign_byupdate::<Sha512, _>(
        &expanded,
        |h: &mut Sha512| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                *h = nonce.clone();
                Ok(())
            } else {
                *seeded.borrow_mut() = Some(h.clone());
                Err(ed25519_dalek::SignatureError::new())
            }
        },
        &verifying,
    );
    let mut challenge = match (probe, seeded.into_inner()) {
        (Err(_), Some(seeded)) => seeded,
        (Err(e), None) => return Err(fail(e)),
        // The callback stops the call at its second message, so this cannot happen; kept
        // total (no panic) all the same.
        (Ok(_), _) => {
            return Err(CoreError::Endpoint(
                "urn:sign:sign: Ed25519 signing did not ask for the message twice".into(),
            ))
        }
    };

    // Pass 2: the challenge hash, and the content hash again to prove the reads agree.
    let mut second = Sha256::new();
    read_pass(message.open(), |chunk| {
        challenge.update(chunk);
        second.update(chunk);
    })
    .await?;
    let (first, second) = (first.finalize(), second.finalize());
    if first != second {
        return Err(CoreError::Conflict(format!(
            "urn:sign:sign: the message read differently on the second of Ed25519's two passes \
             ({HASH_ALG_SHA256}:{} then {HASH_ALG_SHA256}:{}); it changed while it was being \
             signed, so nothing was signed",
            to_hex(&first),
            to_hex(&second)
        )));
    }

    let calls = Cell::new(0u8);
    let sig = raw_sign_byupdate::<Sha512, _>(
        &expanded,
        |h: &mut Sha512| {
            calls.set(calls.get() + 1);
            *h = if calls.get() == 1 {
                nonce.clone()
            } else {
                challenge.clone()
            };
            Ok(())
        },
        &verifying,
    )
    .map_err(fail)?;
    Ok((sig, format!("{HASH_ALG_SHA256}:{}", to_hex(&first))))
}

/// What a verification needs before it reads the message: the algorithm's check, set up from
/// the graph and the key, or the verdict already reached without the crypto. Either is used
/// only once the message's content hash matched — the ORDER of [`verify_message`], whose
/// verdict and errors this reproduces exactly.
enum Check {
    /// Strict Ed25519, one pass: `verify_strict`'s two small-order checks were made up front
    /// (`order_ok`), and its challenge hash runs over the message as it streams.
    Ed25519 {
        verifier: Box<StreamVerifier>,
        order_ok: bool,
        signer_b64: String,
    },
    /// ES256: low-S already checked; the SHA-256 of the message is its digest.
    Es256 {
        key: Box<P256VerifyingKey>,
        signature: P256Signature,
        signer_b64: String,
    },
    /// A verdict reached from the graph and key alone (a different signer, a high-S
    /// signature, an unsupported algorithm, a signature that cannot verify for any message).
    Decided(Verdict),
}

/// The same failure text as [`verify_ed25519`] and [`verify_es256`].
const DOES_NOT_VERIFY: &str = "signature does not verify against the provided public key";

/// Set up the check for `fields` and `key_bytes`: [`verify_ed25519`] / [`verify_es256`] up to
/// the point where they read the message, with the same errors in the same order.
fn prepare_check(fields: &SigFields, key_bytes: &[u8]) -> Result<Check, String> {
    let does_not_verify = || {
        Check::Decided(Verdict::Invalid {
            reason: DOES_NOT_VERIFY.to_string(),
        })
    };
    match fields.algorithm.as_str() {
        ALG_ED25519 => {
            let key = parse_ed25519_public(key_bytes)?;
            let provided = ed25519_signer_b64(&key);
            if let Some(v) = signer_mismatch(fields, &provided) {
                return Ok(Check::Decided(v));
            }
            let sig_bytes = B64
                .decode(fields.value_b64.as_bytes())
                .map_err(|e| format!("sig:value is not valid base64: {e}"))?;
            let signature = Signature::from_slice(&sig_bytes)
                .map_err(|e| format!("sig:value is not a 64-byte Ed25519 signature: {e}"))?;
            // `verify_strict` is the stream verifier plus two checks it makes before hashing:
            // `R` decompresses, and neither `R` nor `A` is of small order (the weak-key
            // forgery). Made here, by the library's own predicates, with the same outcome.
            let order_ok = VerifyingKey::from_bytes(signature.r_bytes())
                .is_ok_and(|r| !r.is_weak())
                && !key.is_weak();
            match key.verify_stream(&signature) {
                Ok(verifier) => Ok(Check::Ed25519 {
                    verifier: Box::new(verifier),
                    order_ok,
                    signer_b64: provided,
                }),
                Err(_) => Ok(does_not_verify()),
            }
        }
        ALG_ES256 => {
            let key = parse_p256_public(key_bytes)?;
            let provided = p256_signer_b64(&key)?;
            if let Some(v) = signer_mismatch(fields, &provided) {
                return Ok(Check::Decided(v));
            }
            let sig_bytes = B64
                .decode(fields.value_b64.as_bytes())
                .map_err(|e| format!("sig:value is not valid base64: {e}"))?;
            let signature = P256Signature::from_slice(&sig_bytes)
                .map_err(|e| format!("sig:value is not a 64-byte P-256 (ES256) signature: {e}"))?;
            if signature.normalize_s().is_some() {
                return Ok(Check::Decided(high_s_verdict()));
            }
            Ok(Check::Es256 {
                key: Box::new(key),
                signature,
                signer_b64: provided,
            })
        }
        other => Ok(Check::Decided(unsupported_algorithm_verdict(other))),
    }
}

/// Verify a streamed message: the body-path twin of [`verify_message`], with its verdicts and
/// errors, reading the message ONCE and holding none of it. The outer `Err` is the message
/// stream's own failure (passed on, never turned into a verdict); the inner `Err` is
/// [`verify_message`]'s, a graph or key too malformed to verify with.
///
/// The graph and key are checked before the message is read, but a problem with them is
/// reported only where [`verify_message`] reports it — after the content hash matched — so
/// the two paths give the same answer for the same inputs. One case needs no read at all:
/// a `sig:contentHash` under an unknown digest tag is refused before the body is opened.
async fn verify_body(
    message: Body,
    fields: &SigFields,
    key_bytes: &[u8],
) -> CoreResult<Result<Verdict, String>> {
    let signed_hex = match content_hash_sha256_hex(&fields.content_hash) {
        Ok(hex) => hex,
        Err(tag) => return Ok(Ok(unsupported_hash_verdict(tag))),
    };
    let mut check = prepare_check(fields, key_bytes);

    let mut digest = Sha256::new();
    read_pass(message, |chunk| {
        digest.update(chunk);
        if let Ok(Check::Ed25519 { verifier, .. }) = &mut check {
            verifier.update(chunk);
        }
    })
    .await?;

    let recomputed = to_hex(&digest.clone().finalize());
    if recomputed != signed_hex {
        return Ok(Ok(Verdict::Invalid {
            reason: format!(
                "content hash mismatch (signed {}, got {HASH_ALG_SHA256}:{recomputed})",
                fields.content_hash
            ),
        }));
    }
    Ok(check.map(|check| match check {
        Check::Decided(verdict) => verdict,
        Check::Ed25519 {
            verifier,
            order_ok,
            signer_b64,
        } => match order_ok && verifier.finalize_and_verify().is_ok() {
            true => Verdict::Valid {
                algorithm: ALG_ED25519.to_string(),
                signer_b64,
            },
            false => Verdict::Invalid {
                reason: DOES_NOT_VERIFY.to_string(),
            },
        },
        Check::Es256 {
            key,
            signature,
            signer_b64,
        } => match key.verify_digest(digest, &signature) {
            Ok(()) => Verdict::Valid {
                algorithm: ALG_ES256.to_string(),
                signer_b64,
            },
            Err(_) => Verdict::Invalid {
                reason: DOES_NOT_VERIFY.to_string(),
            },
        },
    }))
}

// =====================================================================================
// The endpoints — the only kernel-aware layer.
// =====================================================================================

/// The name [`space`] claims: `urn:iki:space:sign`.
pub const SPACE_ID: &str = "urn:iki:space:sign";

/// Mount the module at its conventional IRIs: `urn:sign:sign` (cap-gated) and
/// `urn:sign:verify` (open). A host links this crate and mounts the returned space.
///
/// Configuration-free (two stateless doors, nothing read while building), so the space
/// names itself [`SPACE_ID`]. The name goes on LAST: binding another door drops it.
pub fn space() -> EndpointSpace {
    EndpointSpace::new()
        .bind(Exact::new("urn:sign:sign"), Sign)
        .bind(Exact::new("urn:sign:verify"), Verify)
        .named(space_iri("sign"))
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

        let message = read_bytes(inv, &["in", "content"])?;
        let key_repr = resolve_key(inv, "urn:sign:sign").await?;
        let signer = AnySigner::parse(&key_repr.bytes)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:sign: {e}")))?;

        let graph = sign_to_graph(message, &signer)
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

    /// The body path (ledger #2285): `in` (or `content`) as a body in any of its forms —
    /// inline, by reference, by content id — signed as it is read and never held whole.
    /// Ed25519 reads it twice, so a one-shot body is refused with `InvalidArgument` naming
    /// the argument and `urn:stream:spill`; ES256 reads it once. The answer, the refusals
    /// and their order are [`invoke`](Endpoint::invoke)'s for the same inline input.
    async fn invoke_body(&self, inv: &Invocation<'_>) -> CoreResult<Representation<Body>> {
        if !inv.capability.allows(CAP_SIGN) {
            return Err(CoreError::Denied(format!(
                "urn:sign:sign requires the {CAP_SIGN} capability"
            )));
        }

        let (arg, message) = read_body(inv, &["in", "content"]).await?;
        let key_repr = resolve_key(inv, "urn:sign:sign").await?;
        let signer = AnySigner::parse(&key_repr.bytes)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:sign: {e}")))?;

        let graph = sign_body(message, arg, &signer).await?;
        Ok(Representation::from_body(
            ReprType::new(MEDIA_TURTLE).with_param("charset", "utf-8"),
            graph.into_bytes(),
        )
        // As `invoke`: a pure function of (bytes, key). A message read by reference was read
        // through the kernel too, so its freshness folds in beside the key's.
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
                    .class(XSD_STRING)
                    .reads_body(),
            )
            .input(
                ArgSpec::new("content")
                    .summary("the bytes to sign — the piped-in alternative to `in`")
                    .class(XSD_STRING)
                    .optional()
                    .reads_body(),
            )
            .input(
                ArgSpec::new("key")
                    .summary(
                        "URI (urn: or file: only) of the PRIVATE key resource — PKCS8 Ed25519 \
                         or P-256 (ES256), or SEC1 P-256; PEM or DER; the algorithm is \
                         discovered from the key — resolved through the kernel, e.g. \
                         urn:file:my.pem or urn:secret:…",
                    )
                    .class(RDFS_RESOURCE),
            )
            .output(MEDIA_TURTLE)
            .fails(FailureClass::OverBudget)
            .fails(FailureClass::Unknown)
    }
}

/// `urn:sign:verify` — verify `in` bytes against a `sig` signature-graph using the `key` public
/// key. Open (no capability); verification is public.
struct Verify;

#[async_trait]
impl Endpoint for Verify {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        let message = read_bytes(inv, &["in"])?;
        let sig_turtle = read_str(inv, &["sig", "content"])?;
        let fields = parse_sig_graph(sig_turtle)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:verify: {e}")))?;

        let key_repr = resolve_key(inv, "urn:sign:verify").await?;
        let verdict = verify_message(message, &fields, &key_repr.bytes)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:verify: {e}")))?;

        Ok(Representation::new(
            ReprType::new(MEDIA_PLAIN).with_param("charset", "utf-8"),
            verdict.render().into_bytes(),
        )
        // Pure function of (bytes, sig-graph, key); the key folds in its freshness via
        // `inv.source`. Deterministic ⇒ cacheable.
        .cacheable())
    }

    /// The body path (ledger #2285): `in` as a body in any of its forms, hashed and verified
    /// in ONE pass as it is read, never held whole; `sig` (or `content`) likewise, but
    /// collected under the run's byte budget first, since the graph is parsed whole
    /// (`OverBudget` past it, never a shorter graph). The verdict, the refusals and their
    /// order are [`invoke`](Endpoint::invoke)'s for the same inline inputs.
    async fn invoke_body(&self, inv: &Invocation<'_>) -> CoreResult<Representation<Body>> {
        let (_, message) = read_body(inv, &["in"]).await?;
        let sig_turtle = read_text(inv, &["sig", "content"]).await?;
        let fields = parse_sig_graph(&sig_turtle)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:verify: {e}")))?;

        let key_repr = resolve_key(inv, "urn:sign:verify").await?;
        let verdict = verify_body(message, &fields, &key_repr.bytes)
            .await?
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:verify: {e}")))?;

        Ok(Representation::from_body(
            ReprType::new(MEDIA_PLAIN).with_param("charset", "utf-8"),
            verdict.render().into_bytes(),
        )
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
                 kernel). It parses the graph (exactly one sig:Signature node, its fields read \
                 from that node only), recomputes the content hash and compares it to \
                 the graph's sig:contentHash (sha256:<hex>; an untagged hex digest is read as \
                 SHA-256 for pre-0.2 graphs, any other tag is refused), and — \
                 dispatching on the graph's sig:algorithm — Ed25519- or ES256-verifies the \
                 signature against the public key (parsed as that algorithm), strictly: one \
                 valid signature per (message, key), so a high-S ES256 signature is invalid. \
                 Output is \
                 text/plain — `valid: signed by …` or `invalid: <reason>`. A signature that \
                 doesn't check out is a normal `invalid` answer, not an error; only a malformed \
                 or ambiguous graph, or an unusable key, is an error. Open — no capability \
                 required.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("in")
                    .summary("the bytes to verify")
                    .class(XSD_STRING)
                    .reads_body(),
            )
            .input(
                ArgSpec::new("sig")
                    .summary("the RDF signature-graph (Turtle), named or piped as `content`")
                    .class(XSD_STRING)
                    .reads_body(),
            )
            .input(
                ArgSpec::new("content")
                    .summary("the signature-graph — the piped-in alternative to `sig`")
                    .class(XSD_STRING)
                    .optional()
                    .reads_body(),
            )
            .input(
                ArgSpec::new("key")
                    .summary(
                        "URI (urn: or file: only) of the SPKI PUBLIC key resource (PEM or DER) \
                         of the graph's sig:algorithm — Ed25519 or P-256 (ES256) — resolved \
                         through the kernel",
                    )
                    .class(RDFS_RESOURCE),
            )
            .output(MEDIA_PLAIN)
            .fails(FailureClass::OverBudget)
            .fails(FailureClass::Unknown)
    }
}

// =====================================================================================
// Kernel-aware input helpers.
// =====================================================================================

/// Read the first present inline argument among `names` as raw bytes. `names[0]` is the
/// declared required input; the rest are its alternatives (the piped `content`).
///
/// Every refusal is core's TYPED one, so a caller can tell its own omission from a failure of
/// this module: none of `names` given is `MissingArgument` naming `names[0]` (the input the
/// contract declares required), and a name that IS given but is not an inline value is
/// `InvalidArgument` naming it. A present-but-unusable argument is never skipped in favor of
/// an alternative: that would answer a malformed call with "missing".
fn read_bytes<'a>(inv: &'a Invocation<'_>, names: &[&str]) -> CoreResult<&'a [u8]> {
    first_present(names, |name| inv.inline_arg(name))
}

/// Read the first present inline argument among `names` as a UTF-8 string, with the same typed
/// refusals as [`read_bytes`] (plus `InvalidArgument` for a value that is not UTF-8).
fn read_str<'a>(inv: &'a Invocation<'_>, names: &[&str]) -> CoreResult<&'a str> {
    first_present(names, |name| inv.inline_str(name))
}

/// The first of `names` that `read` finds, skipping only a `MissingArgument`; when every name
/// is missing, the refusal names `names[0]`.
fn first_present<T>(names: &[&str], read: impl Fn(&str) -> CoreResult<T>) -> CoreResult<T> {
    for name in names {
        match read(name) {
            Err(CoreError::MissingArgument(_)) => continue,
            other => return other,
        }
    }
    Err(CoreError::MissingArgument(names[0].to_string()))
}

/// The body behind the first present argument among `names`, with the name it came in: the
/// body-path twin of [`read_bytes`]. An argument in any of its three forms is read
/// ([`Invocation::content_body`]: inline, by reference — a sub-request, recorded — or by
/// content id); none of `names` given is `MissingArgument` naming `names[0]`. Presence is
/// decided by the request, never by an error: a referenced body that fails with a
/// `MissingArgument` of its own is that failure, not a reason to try the alternative.
async fn read_body<'n>(inv: &Invocation<'_>, names: &[&'n str]) -> CoreResult<(&'n str, Body)> {
    for &name in names {
        if inv.request.args.contains_key(name) {
            return Ok((name, inv.content_body(name).await?));
        }
    }
    Err(CoreError::MissingArgument(names[0].to_string()))
}

/// The first present argument among `names` as UTF-8 text: the body-path twin of
/// [`read_str`]. The body is collected under the run's byte budget
/// ([`Invocation::collect`]) — `OverBudget` past it, never truncated — and text that is not
/// UTF-8 is `InvalidArgument` naming the argument, as `read_str` refuses it.
async fn read_text(inv: &Invocation<'_>, names: &[&str]) -> CoreResult<String> {
    let (name, body) = read_body(inv, names).await?;
    let bytes = inv.collect(body).await?;
    String::from_utf8(bytes.to_vec()).map_err(|_| CoreError::InvalidArgument {
        name: name.to_string(),
        detail: "not valid UTF-8".to_string(),
    })
}

/// The URI schemes a `key=` IRI may use. Keys are local resources — a file, a keystore, a
/// secret backend — never a network fetch.
const KEY_SCHEMES: [&str; 2] = ["urn", "file"];

/// Resolve the `key` argument — a resource **URI** — THROUGH the kernel, recording it as a
/// dependency (so a cached result invalidates when the key changes). The value arrives inline
/// as an IRI string (the engine passes `key=urn:…` inline); http(s) is not a key transport, so
/// only `urn:`/`file:` IRIs are accepted ([`KEY_SCHEMES`]) and anything else is a typed
/// `InvalidArgument` on `key` — enforced since 0.2.3; the promise was documented, and not
/// checked, from 0.1.0 (ledger #857). Errors if detached (no kernel context).
async fn resolve_key(inv: &Invocation<'_>, iri: &str) -> CoreResult<Representation> {
    // Core's typed refusal, unchanged: `MissingArgument` when `key` is absent, `InvalidArgument`
    // when it is not an inline UTF-8 value.
    let key_uri = inv.inline_str("key")?;
    let key_iri = Iri::parse(key_uri).map_err(|e| CoreError::InvalidArgument {
        name: "key".to_string(),
        detail: format!("{iri}: bad key IRI `{key_uri}`: {e}"),
    })?;
    // An allowlist, checked BEFORE anything is resolved: a host that binds an http(s) endpoint
    // would otherwise fetch a private key (on `sign`) or a public key (on the OPEN `verify`)
    // over the network on the caller's say-so. Schemes compare case-insensitively (RFC 3986).
    let scheme = key_uri.split_once(':').map_or("", |(scheme, _)| scheme);
    if !KEY_SCHEMES.iter().any(|s| s.eq_ignore_ascii_case(scheme)) {
        return Err(CoreError::InvalidArgument {
            name: "key".to_string(),
            detail: format!(
                "{iri}: key IRI `{key_uri}` uses the `{scheme}:` scheme; a key resolves only \
                 from `urn:` or `file:` (http(s) is not a key transport)"
            ),
        });
    }
    inv.issue(Request::new(Verb::Source, key_iri)).await
}

#[cfg(test)]
mod tests;
