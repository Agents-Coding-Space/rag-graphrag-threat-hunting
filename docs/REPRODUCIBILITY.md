# REPRODUCIBILITY — environment, hashes and float tolerance

This document defines what a fresh checkout must reproduce, and what it must not be expected to
reproduce byte-for-byte. It exists because the review found that a recomputed query produced the
same ordered hits and the same gate decision as the frozen preflight while the stored
`context_sha256` / `messages_sha256` differed.

## 1. What was observed

Twelve fresh queries on a clean install returned:

| Property | Frozen preflight | Fresh recompute | Verdict |
|---|---|---|---|
| Ordered retrieval hit IDs | — | identical | **must match** |
| Gate decision / eligibility | — | identical | **must match** |
| `context_sha256`, `messages_sha256` | frozen | differ | **expected to differ** |

The difference was confined to floating-point scores inside the context, for example
`0.87362147` versus `0.87362149` — a relative difference of about 2e-8. No content, evidence,
ordering or gate outcome changed.

## 2. Why it happens

`retrieve_hybrid` combines BM25 and cosine similarity. The cosine values come from the E5 model
run through numpy/torch on the local CPU. BLAS kernels, thread counts and library builds do not
promise bit-identical reductions, so the last digits of a similarity score can move between
machines while the ranking stays the same.

## 3. The rule

Two separate concepts, never conflated:

1. **Frozen artifact hash.** A file that was written by a run, then stored, is hashed exactly.
   Any byte change is a real tampering signal. These hashes are checked with SHA-256 and are never
   subject to tolerance.
2. **Recomputed numeric value.** A value produced again on a different machine is compared with a
   declared tolerance, and only for the numeric fields named below. Everything else must match
   exactly.

Tolerance is a property of the comparison, not of the artifact. The frozen artifacts themselves
are never rewritten to make a check pass.

## 4. Declared tolerance

```
policy_id:      reproducibility-tolerance/v1
applies_to:     vector similarity scores and RRF component scores inside a context document
absolute tol:   1e-6
relative tol:   1e-6
```

Anything with a larger deviation is a real difference and must be investigated. Ordering,
chunk IDs, evidence IDs, gate reason codes, and every non-numeric field are compared exactly, so
a tolerance on a score can never hide a changed decision.

## 5. Pinned environment

Installed with `pip install -e ".[test,numeric]"` (see `pyproject.toml`). Recorded from the
machine that produced the stored artifacts:

| Component | Version |
|---|---|
| Python | 3.14.0 (CPython, AMD64) |
| OS | Windows 11 10.0.26200 |
| numpy | 2.3.4 |
| torch | 2.12.0+cpu (CUDA not used) |
| torch threads | 4 |
| sentence-transformers | 6.1.0 |
| transformers | 5.17.0 |
| huggingface-hub | 1.7.1 |
| scikit-learn | 1.9.1 |
| scipy | 1.17.1 |
| PyYAML | 6.0.3 |
| fastapi | 0.141.1 |
| uvicorn | 0.49.0 |
| pydantic | 2.12.5 |
| httpx | 0.28.1 |
| python-dotenv | 1.2.1 |
| pytest | 9.0.2 |
| Node / npm (frontend) | 25.0.0 / 11.13.0 |

Python 3.11+ is supported by `requires-python`; the table above is the environment the reported
numbers came from. A different Python or numpy build is allowed to change the last digits of a
score — that is exactly what the tolerance covers — but it does not license a different ranking.

## 6. Embedding model

| Field | Value |
|---|---|
| model | `intfloat/multilingual-e5-small` |
| revision | `614241f622f53c4eeff9890bdc4f31cfecc418b3` |
| dimension | 384 |
| distance metric | cosine |
| normalization | L2 |
| prefixes | `query: ` / `passage: ` |

The revision is pinned in every `vector_index_e5.json` and re-verified against the runtime pin. If
the model cache is missing, the run cannot start; it does not fall back to another model.

## 7. How to refresh the environment record

```cmd
python -B scripts/record_execution_environment.py
```

The script writes `outputs/final/<profile>/execution_environment.json`, reads nothing from the
network, and never touches frozen artifacts. Compare its output with section 5 before claiming a
number was reproduced.

## 8. What is still not reproducible

- The hosted model `cmc/reflection/beam:free` is served by a third party. The same prompt can
  produce different prose over time; only the request parameters are pinned.
- Wall-clock latency depends on that service and on the machine.
- Ground truth remains `draft_reviewable / pending_human_review`; reproducing an output is not the
  same as confirming it is correct.
