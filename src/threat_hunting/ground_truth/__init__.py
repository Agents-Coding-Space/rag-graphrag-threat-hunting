"""Scenario-independent Ground Truth Core contract and validation."""

from .schema import (
    SCENARIO_GROUND_TRUTH_SCHEMA_VERSION,
    GroundTruthValidationError,
    load_ground_truth_document,
    validate_ground_truth_document,
)

__all__ = (
    "SCENARIO_GROUND_TRUTH_SCHEMA_VERSION",
    "GroundTruthValidationError",
    "load_ground_truth_document",
    "validate_ground_truth_document",
)
