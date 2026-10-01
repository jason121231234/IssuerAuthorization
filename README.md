# Issuer Authorization: Reviewer Reproduction Code

Reproduction artifact for *Privacy-Preserving Verification of Fine-Grained Issuer Authorization for AI Agent Credentials*.

## Code and instructions

The latest lightweight implementation is in [code/reviewer](code/reviewer/). Its [README](code/reviewer/README.md) provides dependency installation, tests, the complete example, and computation and communication measurement commands.

The fixed workflow is identified VC issuance followed by blind conversion to an anonymous VP. The holder verifies the entire blind response against its exact request before unblinding. That mandatory check is included once in VP finalization. The implementation uses vector Pedersen commitments, RA-certified issuer attributes, FHS equivalence-class signatures, and complete Groth–Sahai proofs.

## Measurements

The [2026-10-02 measurement report](code/experiment-remeasurement-20261002.md) records the environment, operation boundaries, commands, and results for three, five, and ten permission attributes with a three-coordinate content vector.

- [Formal computation samples and summaries](code/reviewer/results/computation/macos-formal-response-check-20261002/): three warm-up runs and thirty timed runs per operation, with exact source hashes. The sums of operation medians are 1.795, 2.558, and 4.497 seconds, respectively.
- [Communication measurements](code/reviewer/results/communication/macos-response-check-20261002/): total logical payloads of 154,102, 216,622, and 372,994 bytes, respectively.
- The computation directory also records preparation/presentation decomposition, nested complete-refresh costs, and a test-local omitted-refresh diagnostic.

Historical measurements are labeled separately. Operation-median sums are not end-to-end network latency. The package is a locally generated reproduction workflow; its README describes the checks and encoding boundaries.

This release contains code, reproduction instructions, and measurement records. The extended security analysis will be published separately when its document checks are complete.
