"""Compare frozen context documents with a declared float tolerance.

The review found that a fresh recompute produced identical hit ordering and identical gate
decisions while the stored ``context_sha256`` differed, because a cosine score moved by ~2e-8
between machines. Failing that comparison treated a harmless numeric difference as content
drift; disabling the hash check would have hidden real drift.

The rule implemented here separates the two concerns:

* structural fields (hit order, chunk IDs, evidence IDs, gate decisions, reason codes and every
  non-numeric value) must match exactly;
* only numeric scores named in the tolerance policy are compared with a tolerance.

A stored artifact is never rewritten to satisfy this comparison, and a tolerance hit is always
reported as tolerated rather than silently accepted.
"""
from __future__ import annotations

from typing import Any

TOLERANCE_POLICY: dict[str, Any] = {
    "policy_id": "reproducibility-tolerance/v1",
    "applies_to": "vector similarity scores and RRF component scores inside a context document",
    "absolute": 1e-6,
    "relative": 1e-6,
    "numeric_paths": (
        "retrieval/hits/*/score",
        "retrieval/hits/*/chunk/score",
        "retrieval/hits/*/lexical_score",
        "retrieval/hits/*/vector_score",
        "retrieval/hits/*/rrf_score",
    ),
}


def _is_numeric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _close(left: float, right: float, policy: dict[str, Any]) -> bool:
    return abs(left - right) <= max(policy["absolute"], policy["relative"] * max(abs(left), abs(right)))


def _matches_pointer(pointer: str, patterns: tuple[str, ...]) -> bool:
    segments = pointer.strip("/").split("/") if pointer.strip("/") else []
    for pattern in patterns:
        want, got = pattern.split("/"), segments[len(segments) - len(pattern.split("/")):]
        if len(want) != len(got):
            continue
        if all(w == "*" or w != "*" and w == g for w, g in zip(want, got)):
            return True
    return False


def compare_documents(frozen: Any, recomputed: Any, *, path: str = "",
                      policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recursively compare, returning exact and tolerated differences separately."""
    policy = policy or TOLERANCE_POLICY
    exact: list[dict[str, Any]] = []
    tolerated: list[dict[str, Any]] = []

    def walk(left: Any, right: Any, pointer: str) -> None:
        if _is_numeric(left) and _is_numeric(right):
            if left == right:
                return
            if _matches_pointer(pointer, policy["numeric_paths"]) and _close(left, right, policy):
                tolerated.append({"pointer": pointer, "frozen": left, "recomputed": right,
                                  "absolute_difference": abs(left - right)})
            else:
                exact.append({"pointer": pointer, "frozen": left, "recomputed": right})
            return
        if type(left) is not type(right):
            exact.append({"pointer": pointer, "frozen": left, "recomputed": right})
            return
        if isinstance(left, dict):
            if set(left) != set(right):
                exact.append({"pointer": pointer, "frozen": sorted(left), "recomputed": sorted(right),
                              "kind": "key_set"})
            for key in sorted(set(left) & set(right)):
                walk(left[key], right[key], f"{pointer}/{key}")
            return
        if isinstance(left, list):
            if len(left) != len(right):
                exact.append({"pointer": pointer, "frozen": len(left), "recomputed": len(right),
                              "kind": "length"})
            for index, (a, b) in enumerate(zip(left, right)):
                walk(a, b, f"{pointer}/{index}")
            return
        if left != right:
            exact.append({"pointer": pointer, "frozen": left, "recomputed": right})

    walk(frozen, recomputed, path)
    return {
        "policy_id": policy["policy_id"],
        "equivalent": not exact,
        "exact_differences": exact,
        "tolerated_differences": tolerated,
        "tolerance": {"absolute": policy["absolute"], "relative": policy["relative"]},
    }


def assert_equivalent(frozen: Any, recomputed: Any, *, label: str = "context") -> dict[str, Any]:
    """Raise on any structural difference; return the tolerated report otherwise."""
    report = compare_documents(frozen, recomputed)
    if not report["equivalent"]:
        first = report["exact_differences"][0]
        raise ValueError(f"{label} differs beyond the declared tolerance at {first['pointer']}: "
                         f"{first['frozen']!r} != {first['recomputed']!r}")
    return report
