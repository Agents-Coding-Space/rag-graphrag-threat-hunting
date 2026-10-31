"""Evaluation datasets kept separate from production retrieval and GraphRAG."""

from .calibration_config import (
    CALIBRATION_CONFIG_SCHEMA_VERSION,
    CalibrationConfigValidationError,
    generate_policy_candidates,
    load_calibration_config,
    validate_calibration_config,
)
from .calibration_schema import (
    CALIBRATION_REPORT_SCHEMA_VERSION,
    CalibrationReportValidationError,
    build_calibration_report,
    load_calibration_report,
    validate_calibration_report,
)
from .relevance_calibration import RelevanceCalibrationError, calibrate_relevance_policies
from .diagnostics_schema import (
    GRAPHRAG_RELEVANCE_DIAGNOSTICS_SCHEMA_VERSION,
    RelevanceDiagnosticsError,
    load_relevance_diagnostics,
    validate_relevance_diagnostics,
)
from .relevance_diagnostics import analyze_relevance_separability
from .relevance_dataset import (
    RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION,
    RelevanceCalibrationDatasetValidationError,
    load_relevance_calibration_dataset,
    validate_relevance_calibration_dataset,
)
from .retrieval_judgments import (
    RETRIEVAL_JUDGMENTS_SCHEMA_VERSION,
    RetrievalJudgmentsValidationError,
    load_retrieval_judgments_document,
    resolve_retrieval_judgments,
    validate_retrieval_judgments_document,
)
from .embedding_retrieval_comparison_schema import (
    EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION,
    EmbeddingRetrievalComparisonError,
    serialize_embedding_retrieval_comparison_report,
    validate_embedding_retrieval_comparison_report,
)
from .embedding_retrieval_comparison import compare_embedding_retrieval_rankings
from .embedding_retrieval_runner import (
    EMBEDDING_RETRIEVAL_RUN_CONFIG_SCHEMA_VERSION,
    EmbeddingRetrievalRunnerError,
    parse_embedding_retrieval_json_bytes,
    prepare_embedding_retrieval_run,
    run_embedding_retrieval_comparison,
    validate_embedding_retrieval_run_config,
)
from .embedding_model_selection_schema import (
    EMBEDDING_MODEL_SELECTION_POLICY_SCHEMA_VERSION,
    EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION,
    EmbeddingModelSelectionError,
    validate_embedding_model_selection_policy,
    validate_embedding_model_selection,
)
from .embedding_model_selection import evaluate_embedding_model_candidates

__all__ = (
    "EMBEDDING_MODEL_SELECTION_POLICY_SCHEMA_VERSION",
    "EMBEDDING_MODEL_SELECTION_SCHEMA_VERSION",
    "EmbeddingModelSelectionError",
    "evaluate_embedding_model_candidates",
    "validate_embedding_model_selection_policy",
    "validate_embedding_model_selection",
    "EMBEDDING_RETRIEVAL_RUN_CONFIG_SCHEMA_VERSION",
    "EmbeddingRetrievalRunnerError",
    "parse_embedding_retrieval_json_bytes",
    "prepare_embedding_retrieval_run",
    "run_embedding_retrieval_comparison",
    "validate_embedding_retrieval_run_config",
    "GRAPHRAG_RELEVANCE_DIAGNOSTICS_SCHEMA_VERSION",
    "RelevanceDiagnosticsError",
    "analyze_relevance_separability",
    "load_relevance_diagnostics",
    "validate_relevance_diagnostics",
    "CALIBRATION_CONFIG_SCHEMA_VERSION",
    "CALIBRATION_REPORT_SCHEMA_VERSION",
    "CalibrationConfigValidationError",
    "CalibrationReportValidationError",
    "RelevanceCalibrationError",
    "build_calibration_report",
    "calibrate_relevance_policies",
    "generate_policy_candidates",
    "load_calibration_config",
    "load_calibration_report",
    "validate_calibration_config",
    "validate_calibration_report",
    "RELEVANCE_CALIBRATION_DATASET_SCHEMA_VERSION",
    "RelevanceCalibrationDatasetValidationError",
    "load_relevance_calibration_dataset",
    "validate_relevance_calibration_dataset",
    "RETRIEVAL_JUDGMENTS_SCHEMA_VERSION",
    "RetrievalJudgmentsValidationError",
    "load_retrieval_judgments_document",
    "resolve_retrieval_judgments",
    "validate_retrieval_judgments_document",
    "EMBEDDING_RETRIEVAL_COMPARISON_SCHEMA_VERSION",
    "EmbeddingRetrievalComparisonError",
    "compare_embedding_retrieval_rankings",
    "serialize_embedding_retrieval_comparison_report",
    "validate_embedding_retrieval_comparison_report",
)
