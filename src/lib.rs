//! `ikigai-sign` — a capability-gated **Ed25519 signing + verification** module, where a
//! signature is an **RDF graph** and keys are **kernel-resolved resources**.
//!
//! Two endpoints, mounted by [`space`]:
//!
//! 1. **`urn:sign:sign`** (Source, **requires `urn:cap:sign`**) — sign arbitrary bytes.
//!    Inputs: `in` = the bytes to sign (piped `content` fallback) + `key` = the **URI** of a
//!    PKCS8 Ed25519 **private** key resource. The key is dereferenced **through the kernel**
//!    (`inv.source` on the URI, cap-scoped) — so `key=urn:file:my.pem` works today and
//!    `key=urn:secret:…` works unchanged the moment a secrets backend exists. Output is a
//!    **deterministic** RDF signature-graph (`text/turtle`): a `sig:Signature` with
//!    `sig:algorithm`, `sig:signer` (base64 public key), `sig:value` (base64 signature), and
//!    `sig:contentHash` (hex SHA-256 of the signed bytes). No timestamp — Ed25519 is
//!    deterministic, so the same `(bytes, key)` yields byte-identical Turtle, and the graph is
//!    content-addressable/cacheable. The signature node is **skolemized** to a stable,
//!    content-addressed IRI (`urn:sign:<hex>`); no blank nodes.
//!
//! 2. **`urn:sign:verify`** (Source, **open** — no capability) — verify bytes against a
//!    signature-graph. Inputs: `in` = the bytes, `sig` = the signature-graph (piped `content`
//!    fallback), `key` = the URI of a SPKI Ed25519 **public** key resource (kernel-resolved).
//!    It parses the graph, recomputes the content hash of `in`, and Ed25519-verifies the
//!    signature against the public key. Output is `text/plain`: a clear `valid` / `invalid`
//!    verdict. A signature that simply does not check out is **not an error** — it is a `valid:
//!    …` / `invalid: …` answer (`Ok`); only a malformed graph / unreadable key / missing field
//!    is an `Err`. Never panics on hostile input.
//!
//! ## Keys
//!
//! Standard **PKCS8** (private) and **SPKI** (public) Ed25519 keys, in PEM or DER — exactly
//! what `openssl genpkey -algorithm ed25519` emits, and what a `urn:secret:*` custody backend
//! will serve. This module only **consumes** keys; **key generation is out of scope** (it
//! belongs to the secrets module, which owns the key lifecycle — HSM/passkey keys are
//! generated non-exportably and would sign via a delegated act, not here).
//!
//! ## The `sig:` vocabulary
//!
//! Self-contained in this crate under `https://ikigai-rs.dev/ns/sign#` (see [`SIG_NS`]). It is
//! deliberately **not** part of the shared `ikigai-rs.dev/ns` vocabulary and needs no `/ns`
//! deploy: the signature-graph shape has no second consumer yet. If one appears, the
//! `sig:Signature` / `sig:algorithm` / `sig:signer` / `sig:value` / `sig:contentHash` terms are
//! the ones to promote into the published vocab.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use base64::Engine as _;
use ed25519_dalek::pkcs8::{spki::DecodePublicKey, DecodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ikigai_core::{
    ArgSpec, Description, Endpoint, EndpointSpace, Error as CoreError, Exact, Invocation, Iri,
    ReprType, Representation, Request, Result as CoreResult, Verb,
};
use oxrdf::Term;
use oxrdfio::{RdfFormat, RdfParser};
use sha2::{Digest, Sha256};

/// The capability gating "may sign at all." Declared on `urn:sign:sign` via
/// [`Description::requires`] and enforced at entry (the kernel does not yet enforce declared
/// `requires` for bound endpoints, so the endpoint checks it — declared == enforced).
pub const CAP_SIGN: &str = "urn:cap:sign";

/// The signature vocabulary namespace. Self-contained in this crate (no `/ns` deploy).
pub const SIG_NS: &str = "https://ikigai-rs.dev/ns/sign#";

/// `sig:Signature` — the class of the signature node.
const SIG_SIGNATURE: &str = "https://ikigai-rs.dev/ns/sign#Signature";
/// `sig:algorithm` — the signature algorithm name (always `Ed25519` in v1).
const SIG_ALGORITHM: &str = "https://ikigai-rs.dev/ns/sign#algorithm";
/// `sig:signer` — the base64-encoded 32-byte Ed25519 public key of the signer.
const SIG_SIGNER: &str = "https://ikigai-rs.dev/ns/sign#signer";
/// `sig:value` — the base64-encoded 64-byte Ed25519 signature.
const SIG_VALUE: &str = "https://ikigai-rs.dev/ns/sign#value";
/// `sig:contentHash` — the hex-encoded SHA-256 of the signed bytes.
const SIG_CONTENT_HASH: &str = "https://ikigai-rs.dev/ns/sign#contentHash";

/// `rdf:type`.
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
/// The RDF namespace, for the emitted `@prefix rdf:` line.
const RDF_NS: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

/// The only algorithm this module signs/verifies with.
const ALGORITHM: &str = "Ed25519";

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

/// The lowercase-hex SHA-256 of `bytes` — the value of `sig:contentHash`.
fn content_hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    to_hex(&digest)
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

/// Parse PKCS8 Ed25519 **private** key material — PEM (if it is UTF-8 opening with a PEM
/// armor) else DER. A clear message on any failure; never a panic.
fn parse_signing_key(bytes: &[u8]) -> Result<SigningKey, String> {
    if let Some(pem) = as_pem(bytes) {
        SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| format!("not a valid PKCS8 Ed25519 private key (PEM): {e}"))
    } else {
        SigningKey::from_pkcs8_der(bytes)
            .map_err(|e| format!("not a valid PKCS8 Ed25519 private key (DER): {e}"))
    }
}

/// Parse SPKI Ed25519 **public** key material — PEM (if it is UTF-8 opening with a PEM armor)
/// else DER. A clear message on any failure; never a panic.
fn parse_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, String> {
    if let Some(pem) = as_pem(bytes) {
        VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| format!("not a valid SPKI Ed25519 public key (PEM): {e}"))
    } else {
        VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| format!("not a valid SPKI Ed25519 public key (DER): {e}"))
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

/// Sign `message` with `signing_key`, returning the deterministic RDF **signature-graph** as
/// canonical Turtle. Pure and deterministic: same `(message, key)` ⇒ byte-identical output.
fn sign_to_graph(message: &[u8], signing_key: &SigningKey) -> String {
    let signature: Signature = signing_key.sign(message);
    let sig_b64 = B64.encode(signature.to_bytes());
    let signer_b64 = B64.encode(signing_key.verifying_key().to_bytes());
    let content_hash = content_hash_hex(message);

    // Skolemize: the node IRI is content-addressed on the (deterministic) signature bytes, so
    // the graph is stable and diffable and carries no blank node.
    let node = format!("urn:sign:{}", to_hex(&Sha256::digest(signature.to_bytes())));

    let mut out = String::new();
    out.push_str(&format!("@prefix rdf: <{RDF_NS}> .\n"));
    out.push_str(&format!("@prefix sig: <{SIG_NS}> .\n"));
    out.push_str(&format!("<{node}> rdf:type sig:Signature .\n"));
    out.push_str(&format!(
        "<{node}> sig:algorithm {} .\n",
        turtle_string(ALGORITHM)
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

/// Parse a signature-graph (Turtle) into its [`SigFields`], reading the literals of the single
/// `sig:Signature`. Any parse failure or missing required field is a clear `Err`; never panics.
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
    Valid { signer_b64: String },
    Invalid { reason: String },
}

impl Verdict {
    /// The `text/plain` rendering — `valid: …` / `invalid: …`.
    fn render(&self) -> String {
        match self {
            Verdict::Valid { signer_b64 } => {
                format!("valid: signed by {signer_b64} (algorithm {ALGORITHM})\n")
            }
            Verdict::Invalid { reason } => format!("invalid: {reason}\n"),
        }
    }
}

/// Verify `message` against a parsed signature-graph, using `verifying_key` (the caller's
/// `key`). Returns a [`Verdict`] — a signature that simply doesn't check out is a normal
/// `Invalid` answer, not an `Err`. `Err` is reserved for a graph the [`SigFields`] can't be
/// turned into a signature (a shape problem, not a verdict).
fn verify_message(
    message: &[u8],
    fields: &SigFields,
    verifying_key: &VerifyingKey,
) -> Result<Verdict, String> {
    if fields.algorithm != ALGORITHM {
        return Ok(Verdict::Invalid {
            reason: format!(
                "unsupported algorithm `{}` (this module verifies {ALGORITHM})",
                fields.algorithm
            ),
        });
    }

    // Signer pre-check: if the graph names its `sig:signer` and it differs from the public key
    // the caller provided, the signature was made for a DIFFERENT key — a clear, specific
    // verdict (the Ed25519 check below would also fail, but less legibly).
    let provided_signer = B64.encode(verifying_key.to_bytes());
    if let Some(embedded) = &fields.signer_b64 {
        if embedded != &provided_signer {
            return Ok(Verdict::Invalid {
                reason: format!(
                    "provided public key ({provided_signer}) is not the graph's signer ({embedded})"
                ),
            });
        }
    }

    // Content-hash pre-check: a clear, specific verdict when the bytes differ from what was
    // signed (the Ed25519 check below would also fail, but less legibly).
    let recomputed = content_hash_hex(message);
    if recomputed != fields.content_hash {
        return Ok(Verdict::Invalid {
            reason: format!(
                "content hash mismatch (signed {}, got {recomputed})",
                fields.content_hash
            ),
        });
    }

    // Decode the signature bytes. A malformed base64 / wrong-length signature is a shape
    // problem with the graph → `Err`, not a verdict.
    let sig_bytes = B64
        .decode(fields.value_b64.as_bytes())
        .map_err(|e| format!("sig:value is not valid base64: {e}"))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("sig:value is not a 64-byte Ed25519 signature: {e}"))?;

    // `verify_strict`, not `verify`: a signature is this crate's content-address
    // (`urn:sign:{sha256(signature)}`), so verification must admit exactly ONE valid signature per
    // (message, key). The permissive `verify` accepts small-order (weak) keys — a hole that lets a
    // forged signature validate almost any message, minting a bogus `urn:sign:` node. `verify_strict`
    // rejects small-order `A`/`R`; S-scalar canonicity is already enforced above by `from_slice`.
    match verifying_key.verify_strict(message, &signature) {
        Ok(()) => Ok(Verdict::Valid {
            signer_b64: B64.encode(verifying_key.to_bytes()),
        }),
        Err(_) => Ok(Verdict::Invalid {
            reason: "signature does not verify against the provided public key".to_string(),
        }),
    }
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

/// `urn:sign:sign` — Ed25519-sign `in` bytes with the `key` private key, emitting the RDF
/// signature-graph. Requires `urn:cap:sign`, enforced at entry.
struct Sign;

#[async_trait]
impl Endpoint for Sign {
    async fn invoke(&self, inv: &Invocation<'_>) -> CoreResult<Representation> {
        // Enforce the declared capability at entry — `requires` is descriptive; the kernel
        // doesn't yet baseline-check a bound endpoint's declared authority, so we do. A typed
        // `Denied` (permanent, never transient).
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
        let signing_key = parse_signing_key(&key_repr.bytes)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:sign: {e}")))?;

        let graph = sign_to_graph(&message, &signing_key);
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
            .title("Ed25519 sign (RDF signature-graph)")
            .summary(
                "Ed25519-sign bytes with a kernel-resolved PKCS8 private key, emitting a \
                 DETERMINISTIC RDF signature-graph (text/turtle): a sig:Signature with \
                 sig:algorithm, sig:signer (base64 pubkey), sig:value (base64 signature), and \
                 sig:contentHash (hex SHA-256). Pass the bytes as `in` (or pipe them as \
                 `content`) and the private-key resource URI as `key=` (urn:/file: — resolved \
                 THROUGH the kernel, cap-scoped). No timestamp, so the graph is content-\
                 addressable; the node IRI is skolemized (urn:sign:<hash>), no blank nodes. \
                 Requires the urn:cap:sign capability.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .requires(CAP_SIGN)
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
                        "URI of the PKCS8 Ed25519 PRIVATE key resource (PEM or DER), resolved \
                         through the kernel — e.g. urn:file:my.pem or a future urn:secret:…",
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
        let verifying_key = parse_verifying_key(&key_repr.bytes)
            .map_err(|e| CoreError::Endpoint(format!("urn:sign:verify: {e}")))?;

        let verdict = verify_message(&message, &fields, &verifying_key)
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
            .title("Ed25519 verify (RDF signature-graph)")
            .summary(
                "Verify bytes against an RDF signature-graph with a kernel-resolved SPKI public \
                 key. Pass the bytes as `in`, the signature-graph as `sig` (or pipe it as \
                 `content`), and the public-key resource URI as `key=` (resolved through the \
                 kernel). It parses the graph, recomputes the SHA-256 content hash, and \
                 Ed25519-verifies the signature against the public key. Output is text/plain — \
                 `valid: signed by …` or `invalid: <reason>`. A signature that doesn't check \
                 out is a normal `invalid` answer, not an error; only a malformed graph/key is \
                 an error. Open — no capability required.",
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
                        "URI of the SPKI Ed25519 PUBLIC key resource (PEM or DER), resolved \
                         through the kernel",
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
