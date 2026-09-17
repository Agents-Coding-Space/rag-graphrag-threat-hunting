"""Scenario-independent Ground Truth Core contract and validation."""

from .builder import (
    GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION,
    GroundTruthBuildError,
    build_ground_truth_core,
    validate_ground_truth_build_config,
)
from .schema import (
    SCENARIO_GROUND_TRUTH_SCHEMA_VERSION,
    GroundTruthValidationError,
    load_ground_truth_document,
    validate_ground_truth_document,
)

__all__ = (
    "GROUND_TRUTH_BUILD_CONFIG_SCHEMA_VERSION",
    "SCENARIO_GROUND_TRUTH_SCHEMA_VERSION",
    "GroundTruthBuildError",
    "GroundTruthValidationError",
    "build_ground_truth_core",
    "load_ground_truth_document",
    "validate_ground_truth_build_config",
    "validate_ground_truth_document",
)
