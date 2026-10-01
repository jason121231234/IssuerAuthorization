# Reviewer code

This is a fixed-path copy of the prototype used for the paper's identified VC
to anonymous VP experiment. It uses Arkworks for G1/G2 and pairing checks and
py_ecc for standalone pairing/GT operations. There is no runtime mode or
backend selector. The measured operation order is:

1. Vector commitment.
2. Identified VC signing.
3. Identified VC verification.
4. Blind VP request creation.
5. Blind request-proof and authorization verification.
6. Blind signing.
7. Mandatory blind-response verification against the exact request, unblinding,
   signature refresh, VP completion, and hidden opening-proof generation.
8. Anonymous VP verification.

The example and benchmark objects are generated locally. The holder checks the
VC when receiving it; for the later VP request, the issuer binds the request
to its recorded source VC and checks the policy transition, authorization, and
request proof. The holder verifies the blind response on the exact hidden
representative `(U, V, W)` and target policy before unblinding. This check is
included once in the `vp_unblind_and_finalize` timer; it is not replaced by the
verifier's later VP signature and opening-proof checks.
Curve/subgroup input checks outside these protocol equations are omitted, so
this reproduction artifact is not an endpoint for untrusted network inputs.
The serializer encodes payloads for the communication measurement; this copy
does not include a wire decoder or network transport.

## Run

From this directory:

```sh
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export PYTHONPATH=src
export PYTHONDONTWRITEBYTECODE=1

python -m unittest discover -s tests -v
python examples/reviewer_flow.py
python tests/refresh_bypass_diagnostic.py
python benchmarks/compute.py --repetitions 1 --warmup 1 --output-dir results/computation/batches/local-pilot --output-stem quick-results
python benchmarks/compute.py --repetitions 30 --warmup 3 --output-dir results/computation/batches/local-formal --output-stem formal-results
python benchmarks/measure_refresh_boundary.py --repetitions 30 --warmup 3 --output-dir results/computation/batches/refresh-boundary
python benchmarks/communication.py --output-dir results/communication/batches/local-run
```

The example prints `VP verification: True`. Tests cover a valid conversion and
rejection of modified protocol material, including a tampered blind response
rejected by the holder before it creates a VP. The computation benchmark uses
n = 3, 5, and 10 permission attributes and a fixed three-coordinate message
vector (L = 3). The pilot command performs one warm-up and one timed repetition
per operation. The formal command performs three warm-ups and thirty timed
repetitions. Fixture preparation is outside each timer. Each measurement uses
fresh cryptographic randomness and an independently recorded verifier nonce.
The script records raw samples, quartiles, medians, the execution environment,
precise timer boundaries, and source hashes. A one-sample pilot does not
measure variability, even though its two quartiles equal its single value.

The computation script also writes `<output-stem>-decomposition.*` with
repeated timings for advance VP preparation, full holder unblinding and
signature/proof refresh, nonce-bound hidden-opening proof generation, and VP
verification. Full holder unblinding includes exact-request blind-response
verification. These supplementary stages explain parts of the protocol path;
they are not added to the eight-operation sum. The output reports full refresh
as a fraction of that sum. The communication script accepts `--output-dir` so
dated runs preserve earlier results.

`benchmarks/measure_refresh_boundary.py` records the full GS refresh call inside
the real `abs_unblind` path with a timing recorder. It reports both that nested
incremental cost and the enclosing holder unblind/refresh time; the nested
measurement is not added to either enclosing stage or the eight-operation sum.

`tests/refresh_bypass_diagnostic.py` is a deliberately unsafe, test-local
diagnostic for n=3. It replaces the complete GS refresh with an identity stub,
checks the exact `X1` retained-session match and successful VP verification,
then checks the full-refresh control breaks that equality while still
verifying. This demonstrates one concrete incomplete-refresh behavior only; it
does not characterize other partial-refresh variants or establish unlinkability.
Its JSON output is saved beside the dated formal computation results.

The scripts write their outputs under `results/`:

- `<output-dir>/<output-stem>.json`, `.csv`, and `-raw-samples.csv`
- `<communication-output-dir>/latest.json`, `messages.csv`, and
  `role_phase_totals.csv`
- `source-manifest.json` beside each result set, with SHA-256 hashes of every
  Python source, example, test, benchmark, and `requirements.txt` used.

Communication counts the verifier's required policy, epoch, and nonce as the
challenge message, excludes transport framing, and reports network payload
bytes once and endpoint sent/received bytes separately. Public protocol
objects use the canonical encoding. Attribute credentials and commitment
openings use the measurement encodings documented in
`benchmarks/communication.py`.

## Current pilot and historical results

The repaired protocol's Linux pilot is stored under
`results/computation/pilot-linux-quick-1rep-1warmup-20261001/`. It used
CPython 3.12.14 on Linux x86_64 (AMD EPYC 9V74), with the package versions pinned
above. It measured one sample after one warm-up for each operation. The eight
non-overlapping operation times sum to 3.4346 s, 4.9334 s, and 9.0701 s for
n = 3, 5, and 10. These values include mandatory blind-response verification
inside VP finalization and are not end-to-end network latency.

The post-repair Mac formal run is stored under
`results/computation/macos-formal-response-check-20261002/`. On macOS 15.6.1,
Apple M3 Max, CPython 3.11.7, with the pinned package versions, 30 timed samples
and three warm-ups produced eight-operation median sums of 1.795 s, 2.558 s,
and 4.497 s for n = 3, 5, and 10. The sum includes exact blind-response
verification once inside VP finalization and is not end-to-end network latency.
The same dated directory contains the supplementary holder/online decomposition,
the nested full-refresh measurement, and the test-local n=3 refresh-bypass
diagnostic. The corresponding communication capture is under
`results/communication/macos-response-check-20261002/`; payload totals are
154,102 B, 216,622 B, and 372,994 B. Detailed summaries and boundaries are in
`../experiment-remeasurement-20261002.md`.

The pre-existing `results/computation/latest.*` and original communication
results remain historical macOS measurements and are preserved separately.

## Historical verification record (before the response-check repair)

The environment setup was exercised with Python 3.11.16. The final tests,
example, and measurements were rerun on CPython 3.11.7, macOS 15.6.1, arm64,
with `py-ecc 8.0.0` and `py-arkworks-bls12381 0.5.0`. All five tests passed,
the example printed `VP verification: True`, and both benchmarks completed.

The sum of operation medians was 1.522 s, 2.184 s, and 3.884 s for n = 3, 5,
and 10. The corresponding formal-run totals were 1.538 s, 2.202 s, and 3.852
s, giving differences of -1.05%, -0.79%, and +0.84%. The eight-operation
order was identical. These are separate reproduction measurements, not
replacement paper values. Communication totals matched exactly: 154,102 B,
216,622 B, and 372,994 B for n = 3, 5, and 10. The JSON files under `results/`
contain per-operation samples and source hashes for the final copy.

### Response-check repair verification (2026-10-01)

The repaired package passed 6 unittest cases; the original prototype passed
26 targeted pytest cases. Executed commands and summaries are in the pilot
`verification-record.md`. These supersede the historical five-test record
for the repaired code. See `../experiment-remeasurement-20261002.md` for the
current experiment report.

### Current release verification (2026-10-02)

The exported package snapshot passed all 8 unittest cases using the pinned
`long3` Python environment; `examples/reviewer_flow.py` printed
`VP verification: True`. The historical five-test and six-test records above
are retained as records of their earlier runs.
