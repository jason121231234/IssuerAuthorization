# Pilot verification record

All commands ran from `/workspace/icc2027/short3/reviewer-code` in the task-local Linux virtual environment (CPython 3.12.14, py-ecc 8.0.0, py_arkworks_bls12381 0.5.0).

- `PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v` — **6 tests passed** in 5.792 s. Includes normal VC-to-VP flow, altered response rejection before `vp_show`, and the existing request/signature/opening/policy/epoch checks.
- `PYTHONPATH=/workspace/icc2027/long3/code/IssuerAuthentication-S2R/src NATIVE_BLIND_ABS_BACKEND=arkworks .venv/bin/python -m pytest -q /workspace/icc2027/long3/code/IssuerAuthentication-S2R/tests/native_blind_abs/test_paper_core_omissions.py /workspace/icc2027/long3/code/IssuerAuthentication-S2R/tests/native_blind_abs/test_blind_flow.py` — **26 tests passed** in 35.32 s. Covers mandatory response verification in both modes, exact `(U,V,W)`/policy/epoch binding, wrong parameter/schema/epoch/purpose rejection, rejection before unblinding, and the normal flow.
- `python3 -m py_compile benchmarks/compute.py benchmarks/measure_response_check.py` — passed.
- `python3 -m py_compile long3/code/IssuerAuthentication-S2R/src/native_blind_abs/blind.py short3/reviewer-code/src/native_blind_abs/blind.py long3/code/IssuerAuthentication-S2R/tests/native_blind_abs/test_paper_core_omissions.py long3/code/IssuerAuthentication-S2R/tests/native_blind_abs/test_blind_flow.py` — passed.
- `git diff --check` — passed after all code edits.

The original console output was not redirected to a raw test log. This file preserves the executed commands and pass summaries.
