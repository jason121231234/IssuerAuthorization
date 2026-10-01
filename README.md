# Issuer Authorization: Reproduction Code and Security Analysis

Reproduction artifact for *Privacy-Preserving Verification of Fine-Grained Issuer Authorization for AI Agent Credentials*.

## Extended security analysis

Read the [complete security analysis in Markdown](proofs/security-proofs-rewrite.md) directly on GitHub. The matching [standalone LaTeX source](proofs/security-proofs-rewrite.tex) uses `amsmath`, `amssymb`, `amsthm`, `hyperref`, and `geometry` and can be compiled with `pdflatex`.

The supplement expands the paper's authorization/one-more and issuer-privacy/unlinkability arguments into explicit definitions, lemmas, theorems, and proofs. It includes complete proof-refresh algebra, malicious-issuer completed-session privacy, source-content consistency for vector Pedersen commitments, final opening knowledge, selective-disclosure privacy, and historical-verification conditions. Each guarantee states its model and signing interfaces.

- [Algorithm specification](proofs/algorithm-specification.md)
- [Conference-to-extended claim map](proofs/security-claim-map.md)
- [Proof assumptions and interface checklist](proofs/security-proof-checklist.md)

The analysis accompanies manuscript/project revision `29ad482` of `compwjh/icc2027` and the reviewer code released here. Selective disclosure is specified mathematically; the saved computation and payload measurements use the hidden-vector presentation workflow.

## Code and instructions

The latest lightweight implementation is in [code/reviewer](code/reviewer/). Its [README](code/reviewer/README.md) provides dependency installation, tests, the complete example, and computation and communication measurement commands.

The fixed workflow is identified VC issuance followed by blind conversion to an anonymous VP. The holder verifies the entire blind response against its exact request before unblinding. That mandatory check is included once in VP finalization. The implementation uses vector Pedersen commitments, RA-certified issuer attributes, FHS equivalence-class signatures, and complete Groth–Sahai proofs.

## Measurements

The [2026-10-02 measurement report](code/experiment-remeasurement-20261002.md) records the environment, operation boundaries, commands, and results for three, five, and ten permission attributes with a three-coordinate content vector.

- [Formal computation samples and summaries](code/reviewer/results/computation/macos-formal-response-check-20261002/): three warm-up runs and thirty timed runs per operation, with exact source hashes. The sums of operation medians are 1.795, 2.558, and 4.497 seconds, respectively.
- [Communication measurements](code/reviewer/results/communication/macos-response-check-20261002/): total logical payloads of 154,102, 216,622, and 372,994 bytes, respectively.
- The computation directory also records preparation/presentation decomposition, nested complete-refresh costs, and a test-local omitted-refresh diagnostic.

Historical measurements are labeled separately. Operation-median sums are not end-to-end network latency. The package is a locally generated reproduction workflow; its README describes the checks and encoding boundaries.

This release contains code, reproduction instructions, measurement records, and the extended security analysis in Markdown and LaTeX.
