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
| Last reviewed | 2026-11-12 |

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

These are the output rules; the checks and their limits are recorded below:

- A verdict says its outcome as the first word, `valid:` or `invalid:`, and an `invalid` verdict
  always gives its reason in words.
- A refusal names the argument or capability it is about, and the input-related ones say what is
  accepted instead (`a key resolves only from urn: or file:`; make the body re-readable with
  `urn:stream:spill`, or sign with an ES256 key).
- The fixed verdict and refusal text uses words rather than color or layout for meaning.
  The signature-graph is UTF-8 Turtle text. This does not establish that input-derived
  or dependency-provided text is free of terminal control sequences.

## How it is tested

Every named check has a result: Pass, Fail or Blocked, with evidence, following
[the starter's results format](https://github.com/ikigai-rs/ikigai-gonk-starter/pull/91).
A Pass covers only the stated assertions, not overall accessibility or WCAG conformance.

All Pass rows below were run on 2026-11-12 with `cargo test --all-targets`, Cargo 1.99.1
and rustc 1.99.1, on main revision `9631190a0130741dfca66cab4169d4dbf9634d3b`, before
this documentation change. All 75 tests passed. CI repeats these test files through
`cargo test --workspace` in the shared Rust workflow called by `.github/workflows/ci.yml`.
These are correctness tests, not an automated accessibility checker; they do not render a
host interface, evaluate pronunciation or establish usability with assistive technology.

| Check | Result | Evidence |
|---|---|---|
| Verdict outcome in words | Pass | `src/tests.rs`: `round_trip_sign_then_verify_is_valid`, `wrong_public_key_is_invalid`, `es256_round_trip_sign_then_verify_is_valid` and `es256_tampered_content_is_invalid` assert the `valid:` or `invalid:` prefix for their fixtures. They do not exhaust all verdicts. |
| Hash-mismatch and signer-mismatch reasons | Pass | `src/tests.rs`: `tampered_content_is_invalid_by_hash_mismatch`, `signer_mismatch_reports_a_different_embedded_signer` and `verifying_with_a_key_other_than_the_graphs_signer_says_so` assert reason text and signer details; not comprehensibility by ear. |
| High-S refusal reason | Pass | `tests/audit_857.rs`: `es256_high_s_twin_is_refused_with_a_reason` asserts `invalid:` and `high-S`; not whether that terminology is understandable. |
| Missing or unusable input identified | Pass | `src/tests.rs`: `a_missing_required_input_is_a_typed_missing_argument` and `a_given_but_unusable_input_is_a_typed_invalid_argument`; `tests/audit_857.rs`: `a_key_iri_outside_urn_and_file_is_refused_before_resolution` and `an_unparseable_key_iri_is_invalid_argument_on_key`. Check typed errors naming the input, not core's displayed wording. |
| Capability denial and one-shot recovery hint | Pass | `src/tests.rs`: `sign_without_cap_is_typed_denied` checks the error type; `ed25519_refuses_a_one_shot_body_and_names_spill` checks the argument and `urn:stream:spill` hint. They do not evaluate the displayed denial or the ease of following the hint. |
| Signature-graph structure and literal escaping | Pass | `src/tests.rs`: `signature_graph_parses_as_rdf_with_expected_triples`, `turtle_string_escapes_every_reserved_character` and `turtle_string_output_round_trips_through_a_turtle_parser`. Check RDF structure and escaping for fixtures, not human navigation of Turtle. |
| Output media types | Pass | `tests/conformance.rs`: `declared_outputs_are_the_media_types_served` checks declared versus served types; not their presentation in a host. |
| Complete output review for color, control sequences and markup | Blocked | Historical source review recorded 2026-10-31 was not a test and is not repeated by CI. No comprehensive output audit, including input-derived and dependency-provided text, was run for this update. |
| Browser presentation and manual keyboard | Blocked | No host browser or terminal interface was exercised and no person performed a keyboard pass in this update. The library supplies no interactive interface to test on its own. |
| Automated accessibility checker | Blocked | No axe or other accessibility checker was run; no host rendering or checker is configured in this repository. Rust correctness tests do not replace this check. |
| Screen reader | Blocked | No screen reader session was available or used on this output. |
| Screen magnifier | Blocked | No magnifier session was available or used on this output. |
| Speech input | Blocked | No speech-input session was available or used on this output. |
| Switch access | Blocked | No switch-access session was available or used on this output. |
| Braille display | Blocked | No braille display was available or used on this output. |

## Known limitations

Found by reading the source on 2026-10-31:

- **Long opaque strings in sentences.** The `valid:` line carries the whole base64 public key,
  the signer-mismatch verdict carries two, and the hash-mismatch verdict carries two 64-digit hex
  digests. These may be difficult to compare by ear; screen reader behavior has not been
  tested. There is no shorter form (a fingerprint) to compare.
- **Some errors carry a dependency's own wording.** Key and graph parse failures append the
  underlying library's error text (`…: {e}`), which this repository does not control and which
  may not say what to do.
- Every message is English only.

## Contributing

Read this file before changing any output listed above: the verdict, the signature-graph, or a
refusal. Keep the outcome as the verdict's first word, keep meaning in words, and name the input
a refusal is about. In the pull request's accessibility section, give every check a row in a
`Check | Result | Evidence` table: Pass, Fail or Blocked, with the test or command, tool and
version, scope and limits, or why it could not run. Keep unrun checks as Blocked, including
assistive technology nobody used. Historical runs CI does not repeat are Blocked with their
dates; do not carry them forward as Pass. Update this record when the evidence changes.

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
| 2026-11-12 | Record current main test evidence and explicit blocked checks; clarify coverage limits and retain dated source-review limitations. |
