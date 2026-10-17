"""Record this explicitly authorized human approval once; do not rebuild consumers."""

from pathlib import Path
import hashlib
import json

from threat_hunting.ground_truth.approval_update import (
    approve_review_bundle,
    serialize_review_document,
)
from threat_hunting.ground_truth.review_artifacts import validate_review_bundle


ROOT = Path(__file__).resolve().parents[3]
AUDIT = Path(__file__).resolve().parent
REVIEW = ROOT / "outputs/review/mshta-ground-truth"
NAMES = ("scenario_ground_truth.json", "reference_answers.json", "review_manifest.json")


def main() -> None:
    preflight = json.loads((AUDIT / "preflight.json").read_text(encoding="utf-8"))
    documents = []
    for name in NAMES:
        path = REVIEW / name
        original_bytes = path.read_bytes()
        expected = preflight["hashes"][path.relative_to(ROOT).as_posix()]
        assert hashlib.sha256(original_bytes).hexdigest() == expected, f"Preapproval hash mismatch: {name}"
        assert (AUDIT / f"before_{name}").read_bytes() == original_bytes
        document = json.loads(original_bytes)
        assert serialize_review_document(document) == original_bytes, f"Serialization mismatch: {name}"
        documents.append(document)
    approved = approve_review_bundle(
        *documents,
        reviewer="Nguyen Hong Phong",
        reviewed_at=preflight["approval_confirmation_recorded_at"],
        basis="The user explicitly confirmed approval of the reviewed MSHTA Ground Truth and all reference answers in the current conversation and requested this metadata update.",
        timestamp_basis="Current user approval confirmation recorded at the first preflight clock reading: 2026-10-15 16:36:13 UTC, represented as 2026-10-15T23:36:13+07:00. No timestamp for an earlier approval is available; no earlier time is inferred.",
    )
    payloads = [serialize_review_document(document) for document in approved]
    # Validate every output before writing any of the three files.
    validate_review_bundle(
        *(json.loads(payload) for payload in payloads),
        ground_truth_sha256=hashlib.sha256(payloads[0]).hexdigest(),
        reference_answers_sha256=hashlib.sha256(payloads[1]).hexdigest(),
    )
    for name, payload in zip(NAMES, payloads, strict=True):
        (REVIEW / name).write_bytes(payload)
        assert (REVIEW / name).read_bytes() == payload
        print(name, hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    main()
