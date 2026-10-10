# ikigai-sign

**Signing and verification** for [ikigai](https://github.com/ikigai-rs) — a
substrate primitive, not a one-off. Sign any representation, verify it later; a
signature is itself an **RDF graph**, and keys are ordinary **kernel-resolved
resources**.

Two endpoints:

| endpoint | verb | capability | in → out |
|---|---|---|---|
| `urn:sign:sign` | Source | **`urn:cap:sign`** (declared = kernel-enforced) | bytes + `key=<uri>` → an RDF signature-graph |
| `urn:sign:verify` | Source | open | bytes + `sig=<graph>` + `key=<pubkey>` → a verdict |

Signing is authority, so it's capability-gated; verification uses only public
keys, so it's open.

**Two algorithms, and the caller never picks one.** **Ed25519** (small, fast,
deterministic) and, since 0.2.0, **ES256** (ECDSA P-256 — what the Secure Enclave,
TPMs, and WebAuthn speak). On the sign side the algorithm is discovered from the
key; on the verify side it is read from the graph's `sig:algorithm` and dispatched
on. Both sign deterministically, so neither costs the content-addressability below.
A third algorithm is a new id plus a signer and a verifier — never a restructure.

## Keys are resources

`sign` takes `key=<uri>` and resolves it **through the kernel** — so the key can
live anywhere the kernel can reach:

```text
sign key=urn:file:my-key.pem      # a PKCS8 file today
sign key=urn:secret:signing-key   # a Keychain/HSM-backed secret tomorrow (no change)
```

The signer holds no key material of its own — key custody (and generation) belong
to [`ikigai-secret`](https://github.com/ikigai-rs/ikigai-secret). Keys are standard
**PKCS8** (private) / **SPKI** (public), PEM or DER (auto-detected), so
`openssl genpkey -algorithm ed25519` and
`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` produce usable keys
with no bespoke tooling — and which one you handed over is decided by the PKCS8
AlgorithmIdentifier, not by an argument you have to remember. A P-256 private key
is also accepted in **SEC1** (`-----BEGIN EC PRIVATE KEY-----`, PEM or DER), with or
without the `EC PARAMETERS` block in front of it, because that is what the familiar
`openssl ecparam -name prime256v1 -genkey` writes. Its curve is checked rather than
assumed: a SEC1 key or parameters block naming any other curve is refused.

Only `urn:` and `file:` key IRIs are accepted. A key is a local resource, never a
network fetch, so `key=https://…` is refused as an invalid argument before anything
is resolved.

## The signature is a graph

```turtle
@prefix sig: <https://ikigai-rs.dev/ns/sign#> .
<urn:sign:sha256:1fcc…> a sig:Signature ;
  sig:algorithm  "Ed25519" ;                # or "ES256"
  sig:signer     "<base64 public key>" ;
  sig:value      "<base64 signature>" ;
  sig:contentHash "sha256:<hex digest of the signed bytes>" .
```

**Read `sig:algorithm` before reading the other two.** `sig:signer` is in that
algorithm's own encoding — a raw 32-byte key for Ed25519, an SPKI DER document for
ES256 — and `sig:value` is 64 bytes for both (`R‖S` and fixed-width `r‖s`
respectively, never DER), so neither length tells you which you have. An ES256
`s` is always the **low-S** half (see Verify).

**The digest names its algorithm.** `sig:contentHash` is `sha256:<hex>`, not bare
hex: a signature-graph is meant to be checkable by a stranger years from now, and a
naked digest is an unrecoverable commitment to one hash function. The tag is a text
prefix, so the literal stays greppable and joins by string equality with the same
predicate written elsewhere — [`ikigai-log`](https://github.com/ikigai-rs/ikigai-log)
seals carry `sig:contentHash` too.

Verification accepts an **untagged** digest as SHA-256, so graphs signed before
0.2.0 keep verifying; a tag this crate does not implement (`blake3:…`) is **refused**
rather than assumed — otherwise the tag would be decoration.

**So does the identifier.** The node is named `urn:sign:sha256:<hex>` — the same
reasoning one level up, and it matters more there: a literal can be reinterpreted by
a later producer, but a name is quoted, stored and pointed at, so an untagged digest
inside an IRI is the more permanent commitment. Graphs minted before 0.2.1 carry the
bare `urn:sign:<hex>` and **verify unchanged**: nothing reads the subject of a
signature-graph, so this was a discontinuity in a naming scheme, not a migration.

Because it's a graph it lives in the RDF fabric — composes with content-addressed
code-graphs ([`ikigai-sexpr`](https://github.com/ikigai-rs/ikigai-sexpr)), the log,
and verifiable credentials; it's SPARQL-able; and it's **deterministic** (no
timestamp) so the signature-graph is itself content-addressable. The signature
node's IRI is a (tagged) hash **of the signature value** — skolemized, no blank
nodes. Addressing it on the signature is deliberate: verification admits exactly one
valid signature per (message, key), so exactly one node can be minted for a signed
fact. A name derived from anything weaker would let a forgery mint a name for a fact
nobody signed.

## Verify

Verification checks the signature against the **caller-provided** public key over a
recomputed content hash — the embedded `sig:signer` is informational only:

```text
valid: signed by <base64> (algorithm Ed25519)
invalid: content hash mismatch (signed sha256:…, got sha256:…)
invalid: provided public key (…) is not the graph's signer (…)
```

Tampering with the content, the signature value, or presenting the wrong key all
return a clear `invalid`; a malformed graph or unreadable key is a clean error,
never a panic.

**Exactly one valid signature per (message, key), for both algorithms.** The node
is named after its signature, so a second valid signature would be a second name
for the same signed fact. Ed25519 verifies with `verify_strict`. ECDSA is malleable:
if `(r, s)` verifies, so does `(r, n − s)`, and anyone can compute that twin without
the key. So ES256 accepts only the **low-S** form, and `sign` always emits it:

```text
invalid: high-S ES256 signature: s is in the upper half of the group order, …
```

**A signature-graph holds one signature.** Verification finds the node typed
`sig:Signature` and reads its fields from that node only. It refuses a graph with
two such nodes (two parties' graphs concatenated or unioned: verify each against its
own graph), a `sig:` field on any other subject, and a field with two different
values. Other triples, such as a title for the signed document, are left alone. The
node's *name* is still never read, so a graph verifies whatever its node is called.

## Cacheability

A signature is exactly as cacheable as the key it was made with. Both endpoints
mark their results cacheable and declare no golden thread of their own: the key is
the only state they read, it is read through the kernel, and the kernel folds the
key resolution's expiry and threads into the result. Serve keys under a thread (an
`ikigai-fs` cacheable mount, a keystore that cuts on rotation) and signatures cache
until the key rotates; serve them uncacheable (a secret backend read on every call)
and every signature recomputes. The signer holds no key material and watches
nothing — the thread is the keystore's to name and to cut.

## Conformance

Passes [`ikigai-conformance`](https://github.com/ikigai-rs/ikigai-conformance)
(`tests/conformance.rs`): every check, no opt-outs, over both keystore kinds and
both algorithms. The `sig:` terms live under `https://ikigai-rs.dev/ns/sign#` —
this crate's own namespace (`ikigai_sign::SIG_NS`), registered with the suite as
such. It is defined here and in the crate docs, not yet served as a vocabulary
document.

## Portable code, made safe

Combined with `ikigai-sexpr`, this closes the trust half of Code-on-Demand:
**encode a program as a content-addressed graph → sign that graph → ship it →
verify on receipt → run it capability-clamped.**

## Using it from a host

```rust,ignore
let space = ikigai_sign::space(); // binds urn:sign:sign + urn:sign:verify
```

The space names itself `urn:iki:space:sign` (`ikigai_sign::SPACE_ID`): it is configuration-free.

Both endpoints (and the crypto) are wasm-clean.

## 0.3.0 (2026-10-09)

- **The space has a name.** `space()` is configuration-free, so it names itself
  `urn:iki:space:sign`, exported as `ikigai_sign::SPACE_ID` (ledger #987). The name
  is a cache claim: any space named that holds the same two doors. Binding another
  door onto it drops the name (core 0.1.89), so a host that extends the space names
  the result itself.
- Pins: `ikigai-core` 0.1.89, `ikigai-conformance` 0.6.0 (dev).

**Why a minor.** No API was removed, but naming changes what every host sees:
`answered-by`, `urn:kernel:topology`, the space diagrams and cache partitioning all
now carry `urn:iki:space:sign` where they showed an anonymous node. A host takes
that on deliberately, by moving its pin from `0.2` to `0.3`.

## 0.2.3 (2026-10-07, a patch)

Fixes for audit round 3 (ledger #857), each pinned by `tests/audit_857.rs`:

- **ES256 is no longer malleable.** `verify` refuses a high-S signature, the
  key-less `(r, n − s)` twin of a valid one, which minted a second
  content-addressed node for the same (message, key). `sign` emits low-S. For about
  half of all (message, key) pairs this changes the ES256 bytes `sign` produces, and
  so the node's name. It is still deterministic.
- **One signature per graph.** The graph is read per subject: exactly one
  `sig:Signature` node, fields from that node only. Before, the fields were read from
  any subject, and a graph holding two signatures gave a verdict that depended on
  triple order.
- **SEC1 P-256 keys load**, the `openssl ecparam -genkey` output the docs have
  always named, with the curve checked.
- **`key=` takes `urn:` and `file:` only**, as documented since 0.1.0 and never
  checked until now. Anything else is a typed `InvalidArgument` on `key`.

**Why a patch and not 0.3.0.** No API changes. The verdicts that change are for
inputs this crate's own documentation already called invalid: one signature per
(message, key), "the single `sig:Signature`", and only `urn:`/`file:` keys. A
search of every persisted store we hold found **no ES256 signature-graph**, so
nothing already signed stops verifying. Three consumers pin `0.2`. A 0.3.0 would cap
each of them below this security fix until someone edits its manifest; a patch
reaches them on their next resolve.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
