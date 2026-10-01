# Conference-to-Extended Security Claim Map

The conference paper has two short theorems. The current [extended analysis](security-proofs-rewrite.md) separates their games and provides the complete algebra and bounds.

## Conference Theorem 1: authorization and one-more unforgeability

- Extended **Lemma 2**: extract one common issuer vector, selected valid JR certificates, and policy reconstruction.
- Extended **Definition 2 / Theorem 2**: core-EUF; the JR fresh-certificate branch and honest-slot FHS new-class reduction, including encoding and distribution terms.
- Extended **Definition 3 / Theorem 3**: distinct-target blind one-more; count all actual VP responses and guess a fresh target/key pair. Blind responses are signed directly on `(U,V,W)` without request-witness extraction.
- Equations **(17)–(19)** give the advantages and class injectivity.

Required short-theorem precision: use the extraction property of the chosen complete GS setup; identify the Type-III generic-group model for FHS; count actual responses rather than only completed conversions.

## Conference Theorem 2: issuer privacy and unlinkability

- Extended **Lemma 1**: full-rank simulation commitment masks, correction order, and full four-dimensional proof-kernel randomization for arbitrary accepted responses.
- Extended **Definition 6 / Theorem 7**: verifier issuer/support privacy among qualified candidates compatible with all public requirements.
- Extended **Definition 1 / Theorem 1**: request hiding and participating-issuer completed-session unlinkability, with retained issuer keys, source openings, and session records.
- Equations **(11)–(15)** specify completion-weighted advantage and hybrid losses.

Required short-theorem precision: compare common parameter set, policy, time, purpose, field format, and any disclosed coordinates/values. Refer to the extended definition for the completed-session experiment rather than replacing its weighted advantage with a conditional claim.

## Additional long-version guarantees

- **Proposition 1:** correctness, including unchanged vector content with changed Pedersen randomness.
- **Definition 4 / Lemma 3 / Theorem 4:** source-content consistency under source-checked signing; not a consequence of commitment binding alone.
- **Theorem 5:** offline final-opening extraction with the random-oracle fork and complete bad-event budget.
- **Definition 5 / Theorem 6 / Corollary 1:** selective-disclosure content privacy and residual-opening knowledge. The released benchmarks measure the hidden-vector case, not the partial-disclosure extension.
- **Definition 7 / Theorem 8:** composition under the specified interfaces and conditional historical verification with retained authenticated VDR records.
- **Section 7:** exact retained commitment relation for a particular signature-only adaptation diagnostic; full refresh eliminates that deterministic relation, while its security follows from the hybrid proof.

## Document status

The extended Markdown and matching standalone TeX are the newly rewritten analysis. Historical Scheme-2/root-sharing proofs are not used as its premises. The manuscript's two short proof sketches remain unchanged in this release; the games and explicit reduction bounds are stated in the supplement.
