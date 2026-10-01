# Short3 experiment remeasurement — 2026-10-02

## Material Passport

- **ID:** `short3-macos-formal-response-check-20261002`
- **Type:** Reproducible cryptographic-protocol benchmark and payload measurement
- **Status:** Complete
- **Scope:** `short3/reviewer-code/` measurements, benchmark support, tests, and this technical report. No paper prose, security proof, network experiment, commit, or push was performed.

## Environment and execution

The run used macOS 15.6.1 on a MacBook Pro (Mac15,10), Apple M3 Max, 14 CPU cores and 36 GB memory; CPython 3.11.7; `py-ecc` 8.0.0; `py-arkworks-bls12381` 0.5.0. The existing pinned environment at `long3/code/IssuerAuthentication-S2R/.venv` was validated and used read-only because `short3/reviewer-code/.venv` did not exist. A new reviewer environment could not install from PyPI in the network-restricted runtime; the validated local environment supplied both exact pinned packages.

The computation used the fixed identified VC → anonymous VP path, `n ∈ {3,5,10}`, `L=3`, 30 timed repetitions and 3 warm-ups. Each row prepares its fixture before timing, uses fresh protocol randomness, and supplies a fresh 32-byte verifier nonce saved independently for verification. The exact blind response is checked against its request inside `vp_unblind_and_finalize`, once. The eight-operation sum is the sum of row medians; it is an operation-level core-cost summary, not end-to-end latency.

Commands were run from `short3/reviewer-code` with `PYTHONPATH=src` and `PYTHONDONTWRITEBYTECODE=1`:

```sh
/Users/wjh/work/latex/icc\ 2027/long3/code/IssuerAuthentication-S2R/.venv/bin/python -m unittest discover -s tests -v
/Users/wjh/work/latex/icc\ 2027/long3/code/IssuerAuthentication-S2R/.venv/bin/python examples/reviewer_flow.py
/Users/wjh/work/latex/icc\ 2027/long3/code/IssuerAuthentication-S2R/.venv/bin/python benchmarks/compute.py --repetitions 30 --warmup 3 --output-dir results/computation/macos-formal-response-check-20261002 --output-stem formal-response-check
/Users/wjh/work/latex/icc\ 2027/long3/code/IssuerAuthentication-S2R/.venv/bin/python tests/refresh_bypass_diagnostic.py
/Users/wjh/work/latex/icc\ 2027/long3/code/IssuerAuthentication-S2R/.venv/bin/python benchmarks/measure_refresh_boundary.py --repetitions 30 --warmup 3 --output-dir results/computation/macos-formal-response-check-20261002/refresh-boundary
/Users/wjh/work/latex/icc\ 2027/long3/code/IssuerAuthentication-S2R/.venv/bin/python benchmarks/communication.py --output-dir results/communication/macos-response-check-20261002
```

## Eight-operation computation results

All operation values are milliseconds, reported as median (IQR), with 30 timed samples per cell.

| Operation | n=3 | n=5 | n=10 |
|---|---:|---:|---:|
| Vector commitment | 0.451 (0.011) | 0.467 (0.030) | 0.464 (0.026) |
| Identified VC sign | 334.289 (1.685) | 459.637 (4.073) | 773.324 (3.762) |
| Identified VC verify | 333.898 (2.141) | 458.830 (2.758) | 774.658 (3.145) |
| VP request creation | 12.431 (0.244) | 16.332 (0.376) | 26.740 (0.441) |
| VP request verification | 15.944 (0.238) | 21.359 (0.344) | 35.103 (0.819) |
| VP blind sign | 270.880 (1.952) | 394.824 (2.242) | 710.525 (3.535) |
| VP unblind and finalize | 557.323 (2.567) | 812.617 (5.522) | 1461.290 (8.567) |
| Anonymous VP verify | 269.712 (2.476) | 394.210 (2.456) | 715.159 (3.314) |
| **Sum of eight operation medians** | **1794.927 ms (1.795 s)** | **2558.277 ms (2.558 s)** | **4497.263 ms (4.497 s)** |

The total is the sum of medians, so no aggregate IQR is assigned to it. Per-operation IQRs are calculated as Q3−Q1 from each row’s 30 raw samples.

## Preparation, online presentation, and refresh decomposition

The supplementary timings below are independent measurements of existing APIs. They are explanatory and are not added to the eight-operation total. “Advance preparation” is the `vp_request` cryptographic preparation before a verifier nonce is supplied. Holder unblinding includes the mandatory exact-request response check, unblinding, and complete signature/proof refresh. `vp_show` includes generation of the nonce-bound hidden-opening proof and presentation packaging. Verification is the existing verifier API.

Values are median (IQR), milliseconds, 30 timed samples per cell.

| Stage | n=3 | n=5 | n=10 |
|---|---:|---:|---:|
| Advance VP preparation | 9.076 (0.134) | 11.884 (0.231) | 18.789 (0.290) |
| Holder unblind + full refresh, including response check | 549.410 (2.981) | 802.653 (4.165) | 1445.717 (5.917) |
| Nonce-bound hidden-opening generation | 3.619 (0.070) | 5.024 (0.086) | 8.500 (0.148) |
| Anonymous VP verification | 268.610 (4.385) | 394.567 (2.516) | 713.308 (2.448) |
| **Nested complete GS refresh call** | **271.262 (2.709)** | **399.378 (3.076)** | **721.493 (5.207)** |

The final row records the real `blind.refresh` call from inside `abs_unblind`, using a timing recorder; response verification and unblinding are outside this nested interval. This is the measured incremental complete-refresh cost. It is **not** added again to the enclosing holder-stage time or the eight-operation total.

| Refresh-cost fraction | n=3 | n=5 | n=10 |
|---|---:|---:|---:|
| Nested GS refresh / eight-operation median sum | 15.11% | 15.61% | 16.04% |
| Nested GS refresh / `vp_unblind_and_finalize` median | 48.67% | 49.15% | 49.37% |
| Full holder unblind/refresh stage / eight-operation median sum | 30.61% | 31.37% | 32.15% |

## Test-local retained-session diagnostic

The diagnostic fixes `n=3` and replaces the complete GS refresh with an identity stub local to `tests/refresh_bypass_diagnostic.py`; production code is unchanged. It compares both G2 points of the `X1` authorization commitment in the issuer’s blind response and the resulting VP signature.

| Path | `X1` equals issuer response | VP verifies | Refresh path observed |
|---|---:|---:|---|
| Deliberately incomplete diagnostic | Yes | Yes | Test-local identity stub, one call |
| Complete-refresh control | No | Yes | Actual full refresh, one call |

This demonstrates one exact retained-session matching relation for the deliberately incomplete path. It does not claim that all partial-refresh variants are unsafe, and successful verification is not an unlinkability result. No classifier or attack-accuracy claim is made. The machine-readable result is `results/computation/macos-formal-response-check-20261002/refresh-bypass-diagnostic.json`.

## Communication payloads

These are encoded logical payload bytes, excluding transport framing; they do not represent network latency. The challenge counts required policy, epoch, and nonce. Endpoint sent+received totals count each payload at both endpoints.

| Phase bytes | n=3 | n=5 | n=10 |
|---|---:|---:|---:|
| Setup | 2,026 | 2,026 | 2,026 |
| Issuer registration | 6,096 | 8,272 | 13,712 |
| VC issuance | 40,201 | 55,243 | 92,872 |
| VP issuance | 72,789 | 102,873 | 178,119 |
| Presentation delivery | 32,990 | 48,208 | 86,265 |
| **Network payload total** | **154,102** | **216,622** | **372,994** |
| Endpoint sent+received total | 308,204 | 433,244 | 745,988 |

## Verification, raw data, and manifests

- Final reviewer package suite: **8 unittest cases passed** in 14.509 s. This includes the modified communication output-directory test and the refresh-bypass/full-refresh control test.
- Example: `VP verification: True`.
- The benchmark’s supplementary complete-refresh path verifies every measured output after the timed interval. The compute smoke run also wrote all expected decomposition and raw files.
- Only reviewer-package tests were run; this is not a claim that the full `long3` prototype suite passed.
- No network tests were run.

Raw samples, summaries, metadata, and manifests:

- Main computation: `short3/reviewer-code/results/computation/macos-formal-response-check-20261002/formal-response-check.{json,csv}` and `formal-response-check-raw-samples.csv`.
- Eight-operation source manifest (SHA-256): `short3/reviewer-code/results/computation/macos-formal-response-check-20261002/source-manifest.json`; the run metadata also embeds the exact source hashes.
- Supplementary decomposition and raw samples: files named `formal-response-check-decomposition.*` in the same directory.
- Nested refresh measurements and exact source hashes: `short3/reviewer-code/results/computation/macos-formal-response-check-20261002/refresh-boundary/refresh-boundary.json` and adjacent CSV/raw CSV. Its metadata embeds the SHA-256 manifest for this later recorder run.
- Diagnostic source hashes and result: `short3/reviewer-code/results/computation/macos-formal-response-check-20261002/refresh-bypass-diagnostic.json`.
- Communication payloads and source manifest: `short3/reviewer-code/results/communication/macos-response-check-20261002/`.

## Changed paths

Benchmark/documentation/test changes for this task are confined to `short3/reviewer-code/`: `README.md`, `benchmarks/compute.py`, `benchmarks/communication.py`, new `benchmarks/measure_refresh_boundary.py`, `tests/test_reviewer_flow.py`, new `tests/__init__.py`, and new `tests/refresh_bypass_diagnostic.py`. Measurement outputs are under the two dated `results/` directories listed above. This technical report is the only file this task changed outside `short3/reviewer-code/`.
