# Security Proof Checklist

This checklist records the proof interfaces of [Extended Security Analysis](security-proofs-rewrite.md). “Checked” means that the stated argument was traced against the frozen equations and cited component result; it does not designate an independent cryptographic certification. Execution tests are recorded separately in the reviewer package.

## Common setup and acceptance

- **Checked — parameter authenticity.** All games fix one trusted authenticated parameter set; `pp-id` binds the RA and GS keys, field formats, and Pedersen bases. Historical verification uses retained authenticated period records.
- **Checked — JR distribution.** The attribute certifier uses the full JR/QA key-generation distribution, not independently chosen public elements. The released setup's extra nonzero conditioning is bounded by `delta_par <= 18/p`. The proof explicitly includes this negligible distribution term.
- **Checked — message domains.** Ordinary representatives are `(C,g1,J)`; their coordinates are nonidentity. Blind representatives have nonidentity `U,V,W` and `W=V^j`. Public `gamma` is nonidentity; hidden `Z` is allowed to be identity.
- **Checked — complete GS extraction.** Extraction recovers group witnesses from the exact PPEs, including shared key commitments. No discrete logarithms of extracted reconstruction weights are required: selected rows are recognized through their bits and the public matrix is solved directly.
- **Checked — fixed layout.** Every policy row, including unselected rows, has the same prescribed positions. Refresh is indexed by variable identity, not by equality of group bytes.
- **Checked — exact blind response.** The holder checks the entire response against its exact request and target before transformation. The current reviewer code includes that mandatory verification in `VP finalize`.

## Proposition 1: correctness

- Substitute the FHS signature into its two pairing equations.
- Normalize the blind representative with `mu=1/s` and the signature with independent `psi`.
- Scale the message and consistency proof matrices by the prescribed factors.
- Use the refresh correction identity with **new second-group** and **previous first-group** commitments.
- Set the final Pedersen randomness to `r0+Delta`; every content coordinate is unchanged.

## Lemma 1 and Theorem 1: refresh and blindness

- **Rank:** simulation mask matrices have determinants `-xi` and `-zeta`.
- **Commitments:** independent mask pairs cover the full commitment space in simulation mode.
- **Proofs:** the eight-to-four verification map is surjective; its kernel has dimension four. The four independent equation masks map injectively onto that entire kernel.
- **Malicious responses:** the matrix correction and kernel argument apply to every response passing the holder's full check, not only honestly generated proofs.
- **Public randomizer:** independent nonzero `psi` makes `gamma'` uniform for any accepted nonidentity starting value.
- **Interfaces:** request hiding retains the issuer's known source. Session unlinkability retains its keys, source openings, records, and arbitrary response choices.
- **Completion:** use the unconditional completion-weighted advantage in Definition 1; both failures return a common result.
- **Hybrid order:** switch the CRS; simulate request/opening proofs; replace final proofs using the complete-refresh lemma; only then replace `U=C1^s` by DDH. `W=V^j` is still computed exactly, with no `g2^s` released.
- **Budgets:** include CRS-domain correction, two DDH targets, target sampling restrictions, challenge mapping, and programming collisions against the common occupied oracle cache.

## Lemma 2 and Theorem 2: authorization and core-EUF

- **JR branch:** a selected certificate on an uncertified complete-vector/attribute/time message gives a fresh JR forgery.
- **FHS branch:** outside that event, the selected rows belong to one ledger vector satisfying the target; the victory restriction makes it an uncorrupted honest vector.
- **Embedding:** guess the honest registration slot. The reduction generates RA/GS locally, certifies the external group key, and proves using oracle-returned group signature components. It need not know that issuer's secret exponents.
- **Corruption:** abort only for the guessed slot; a correct guess for the uncorrupted winning vector does not trigger that abort.
- **Classes:** the fixed second coordinate `g1` forces class scale one. The encoded third coordinate separates policy, time, purpose, and format outside encoding collisions.
- **Model:** the FHS result is its Scheme-1 new-class theorem in the Type-III generic-group model. Outer operations and all three group-oracle budgets are included.
- **Bound:** `epsilon_A + N epsilon_FHS`, with JR, encoding, registration, and parameter-distribution terms in `epsilon_A`.

## Theorem 3: blind one-more

- Count every actual VP signature response, including repeats, ordinary VP responses, and subsequently abandoned conversions.
- Count distinct normalized targets, not signature bytes, supports, or presentation nonces.
- Simulate one blind response with exactly one FHS query on `(U,V,W)`; no request-witness extraction is used in this reduction.
- Ordinary VC signatures cannot cover a VP class because the purpose is encoded in `J`.
- More distinct target/key pairs than responses leaves one unqueried pair. Guess its honest slot and output position; the FHS game checks freshness without requiring the reduction to compute a discrete-logarithmic normalization factor.
- Bound: `epsilon_A + N L_out,max epsilon_FHS`.

## Lemma 3 and Theorems 4–5: vector content and knowledge

- **Interface:** legitimate sources have explicit recorded openings, and all honest VP responses pass source-record and transition checks. The experiment's policy restriction excludes a fully authorized controlled issuer.
- **Content model:** work generically relative to erased Pedersen exponents. First-group coefficients are affine; second-group values have no content-base partners; pairing values are affine. Analysis-only class comparisons have degree at most two.
- **Request challenges:** fixed first messages force `V=g1^s` and `U`'s content coefficients to equal `s*m0`, except for at most two field-challenge guesses per queried transcript and the stated collision events.
- **Response association:** outside JR/FHS forgery, extracted output classes match actual source-checked responses; their normalized content coefficients equal that recorded vector.
- **Explicit opening:** a different claimed vector produces a nonidentity content-base relation, covered by the polynomial collision budget.
- **Offline extraction:** fork the complete rerunnable experiment at the final transcript-bound opening query. Eligibility is checked from public-policy and interface records, not presumed content equality.
- **Fork losses:** retain the general-fork expression and `(Q+1)*beta`; each fixed-index second run has an ordinary-run marginal. Do not condition bad-event bounds on rare acceptance.
- **First ledger:** associate the extracted vector with a response in the first execution, not one newly introduced by the second execution.
- **Separation:** this offline extractor is not inserted into the unknown-key FHS reductions.

## Theorems 6–7 and Corollary 1: privacy and disclosure

- The content comparison uses honest completed challenge presentations with equal format and equal disclosed coordinates/values; the source opening is absent from the verifier's challenge view.
- Fresh Pedersen randomness hides the full vector; a transcript-bound residual-opening proof simulates the undisclosed coordinates.
- `D=empty` is the implemented and measured hidden-vector case.
- Partial disclosure is defined explicitly by the residual commitment. Its knowledge argument adjoins the transcript-fixed disclosed coordinates after the opening fork.
- Verifier issuer/support privacy compares candidates compatible with **all** public requirements. Candidate keys and attribute sets may be known; challenge source/session records are not silently inserted into that game.
- Participating-issuer unlinkability uses the separate stronger view and completion-weighted game of Definition 1.

## Theorem 8 and historical verification

- State each guarantee with its own acceptance and oracle rules. One-more, content preservation, and disclosure privacy are not silently combined into one unrestricted game.
- VDR authenticity and historical-record retention allow the same cryptographic equations to be checked for the chosen period.
- Record availability is a system assumption. The period encoding is not a proof of physical issuance time.

## Diagnostic evidence and implementation review

The signature-only adaptation diagnostic deliberately skips the complete refresh while retaining the signature transformation. Its commitment to `X1` is byte-for-byte unchanged from the stored response, giving an exact session-matching test. The production workflow refreshes that commitment and all equations. This diagnostic is evidence for that specific omitted-refresh variant; the mathematical unlinkability result is Theorem 1.

Source anchors in the reviewer package:

- `src/native_blind_abs/setup.py`: JR joint setup, GS parameters, erased content-base generation.
- `src/native_blind_abs/jr.py`: exchanged-group certificate generation and verification.
- `src/native_blind_abs/core.py`: selected-row equations, complete key association, FHS message equations, layout.
- `src/native_blind_abs/blind.py`: request checking, exact full response verification, transformation and refresh.
- `src/native_blind_abs/gs.py`: complete PPE verification and four-mask refresh.
- `src/native_blind_abs/proofs.py` and `hashing.py`: transcript bindings and field challenge mapping.
- `src/native_blind_abs/services.py`: source-record and transition checks.

The public README identifies the released revision and reproduction commands. Tests and formal measurement records establish the behavior and cost of that revision on their covered inputs; mathematical claims use the definitions and reductions above.
