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
keys, so it's open. The scheme is **Ed25519** (small, fast, deterministic).

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
`openssl genpkey -algorithm ed25519` produces a usable key with no bespoke tooling.

## The signature is a graph

```turtle
@prefix sig: <https://ikigai-rs.dev/ns/sign#> .
<urn:sign:1fcc…> a sig:Signature ;
  sig:algorithm  "Ed25519" ;
  sig:signer     "<base64 public key>" ;
  sig:value      "<base64 signature>" ;
  sig:contentHash "sha256:<hex digest of the signed bytes>" .
```

**The digest names its algorithm.** `sig:contentHash` is `sha256:<hex>`, not bare
hex: a signature-graph is meant to be checkable by a stranger years from now, and a
naked digest is an unrecoverable commitment to one hash function. The tag is a text
prefix, so the literal stays greppable and joins by string equality with the same
predicate written elsewhere — [`ikigai-log`](https://github.com/ikigai-rs/ikigai-log)
seals carry `sig:contentHash` too.

Verification accepts an **untagged** digest as SHA-256, so graphs signed before
0.2.0 keep verifying; a tag this crate does not implement (`blake3:…`) is **refused**
rather than assumed — otherwise the tag would be decoration.

Because it's a graph it lives in the RDF fabric — composes with content-addressed
code-graphs ([`ikigai-sexpr`](https://github.com/ikigai-rs/ikigai-sexpr)), the log,
and verifiable credentials; it's SPARQL-able; and it's **deterministic** (no
timestamp) so the signature-graph is itself content-addressable. The signature
node's IRI is a hash of the signature value — skolemized, no blank nodes.

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

## Portable code, made safe

Combined with `ikigai-sexpr`, this closes the trust half of Code-on-Demand:
**encode a program as a content-addressed graph → sign that graph → ship it →
verify on receipt → run it capability-clamped.**

## Using it from a host

```rust,ignore
let space = ikigai_sign::space(); // binds urn:sign:sign + urn:sign:verify
```

Both endpoints (and the crypto) are wasm-clean.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
