# Accessibility

What `ikigai-sign` emits that people read, the rules that output follows, how it is tested, and
how to report a barrier. It is not a conformance claim. Adapted from the
[ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA, for any page that presents this output; this repository writes text only (no HTML, SVG or color) |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-sign/issues/new?labels=accessibility) with the `accessibility` label; anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-sign/security/advisories/new) |
| Last reviewed | 2026-10-31 |

## What it emits that people read

This is a library: two endpoints a host binds. Everything it emits is text, all of it in
`src/lib.rs`.

- **The verdict** from `urn:sign:verify`, as `text/plain` (`Verdict::render`): one line,
  `valid: signed by <base64 public key> (algorithm Ed25519)` or `invalid: <reason>`, where the
  reason is a sentence such as `content hash mismatch (signed sha256:…, got sha256:…)`,
  `provided public key (…) is not the graph's signer (…)` or the high-S refusal.
- **The signature-graph** from `urn:sign:sign`, as `text/turtle` (`render_graph`): five
  triples about one `sig:Signature` node. It is meant for machines, but people read it too.
- **Refusals and errors**: a missing input is core's `MissingArgument` naming the input (`in`,
  `key`, `sig`); an unusable one is `InvalidArgument` naming it with a sentence (a bad key IRI, a
  key scheme other than `urn:` or `file:`, a one-shot body under an Ed25519 key, which names
  `urn:stream:spill` as the fix); a missing capability is `Denied`, naming `urn:cap:sign`; a key
  or graph that does not parse is an error prefixed with the endpoint's IRI
  (`urn:sign:sign: not a valid SPKI Ed25519 public key (PEM): …`).

Not this repository's: how a host shows any of this (a terminal, a web page, a log). The
wording of core's `MissingArgument`, `InvalidArgument` and `Denied` displays is
`ikigai-core`'s.

## The rules that output follows

Verified by reading the source:

- A verdict says its outcome as the first word, `valid:` or `invalid:`, and an `invalid` verdict
  always gives its reason in words.
- A refusal names the argument or capability it is about, and the input-related ones say what is
  accepted instead (`a key resolves only from urn: or file:`; make the body re-readable with
  `urn:stream:spill`, or sign with an ES256 key).
- No color, no terminal control sequences and no markup are written; the Turtle is plain
  UTF-8 text.

## How it is tested

- `src/tests.rs`: `round_trip_sign_then_verify_is_valid`, `wrong_public_key_is_invalid`,
  `tampered_content_is_invalid_by_hash_mismatch` and the ES256 equivalents pin the `valid:` and
  `invalid:` first words; `signer_mismatch_reports_a_different_embedded_signer` pins that
  reason's wording; `a_missing_required_input_is_a_typed_missing_argument` and
  `a_given_but_unusable_input_is_a_typed_invalid_argument` pin that a refusal names its input;
  `ed25519_refuses_a_one_shot_body_and_names_spill` pins that the refusal names the fix.
- `tests/audit_857.rs`: `es256_high_s_twin_is_refused_with_a_reason` pins that the high-S
  verdict says `high-S`.

These test wording for correctness; none was written as an accessibility test.
**No automated accessibility checker, browser or assistive technology has been used on this
output.**

## Known limitations

Found by reading the source on 2026-10-31:

- **Long opaque strings in sentences.** The `valid:` line carries the whole base64 public key,
  the signer-mismatch verdict carries two, and the hash-mismatch verdict carries two 64-digit hex
  digests. A screen reader reads these character by character, and there is no shorter form
  (a fingerprint) to compare by ear.
- **Some errors carry a dependency's own wording.** Key and graph parse failures append the
  underlying library's error text (`…: {e}`), which this repository does not control and which
  may not say what to do.
- Every message is English only.

## Contributing

Read this file before changing any output listed above: the verdict, the signature-graph, or a
refusal. Keep the outcome as the verdict's first word, keep meaning in words, and name the input
a refusal is about. Say in the pull request what was tested, with what, and what was not.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-sign/issues/new?labels=accessibility) with
the `accessibility` label (the link sets it when GitHub lets you add labels; otherwise a
maintainer adds it): what you were doing, what happened, and the host and any assistive
technology you used, if you are comfortable sharing them. Anything security-sensitive goes
through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-sign/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.

## Change history

| Date | Change |
|---|---|
| 2026-10-31 | First version. |
