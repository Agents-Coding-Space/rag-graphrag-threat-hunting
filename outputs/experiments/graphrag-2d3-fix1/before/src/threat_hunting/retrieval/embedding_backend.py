"""Lazy local Sentence Transformers embedding backend."""

from __future__ import annotations

from collections.abc import Callable, Sequence
import math
import os
import re
from typing import Any


COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class EmbeddingBackendError(RuntimeError):
    """Raised when a local embedding model cannot load or encode safely."""


def _default_model_factory(
    model_id: str,
    *,
    revision: str,
    device: str,
) -> object:
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
    os.environ["DO_NOT_TRACK"] = "1"
    try:
        from sentence_transformers import SentenceTransformer
    except (ImportError, OSError) as exc:
        raise EmbeddingBackendError(
            "sentence-transformers is unavailable; install the pinned project dependency"
        ) from exc
    return SentenceTransformer(
        model_id,
        revision=revision,
        device=device,
        trust_remote_code=False,
    )


def _nonempty_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EmbeddingBackendError(f"{field} must be a non-empty string")
    return value


def _positive_integer(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise EmbeddingBackendError(f"{field} must be a positive integer")
    return value


def _to_plain_sequence(value: object) -> object:
    converted = value
    for method_name in ("detach", "cpu"):
        method = getattr(converted, method_name, None)
        if callable(method):
            converted = method()
    tolist = getattr(converted, "tolist", None)
    if callable(tolist):
        converted = tolist()
    return converted


def _is_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    )


class SentenceTransformerEmbeddingBackend:
    """Embed document text locally using a revision-pinned model on one device."""

    def __init__(
        self,
        *,
        model_id: str,
        model_revision: str,
        dimension: int,
        device: str,
        batch_size: int,
        show_progress_bar: bool,
        model_factory: Callable[..., object] | None = None,
    ) -> None:
        self.model_id = _nonempty_string(model_id, field="model_id")
        revision = _nonempty_string(model_revision, field="model_revision")
        if COMMIT_SHA_PATTERN.fullmatch(revision) is None:
            raise EmbeddingBackendError(
                "model_revision must be a full 40-character hexadecimal commit SHA"
            )
        self.model_revision = revision.lower()
        self.dimension = _positive_integer(dimension, field="dimension")
        self.device = _nonempty_string(device, field="device")
        self.batch_size = _positive_integer(batch_size, field="batch_size")
        if not isinstance(show_progress_bar, bool):
            raise EmbeddingBackendError("show_progress_bar must be a boolean")
        self.show_progress_bar = show_progress_bar
        if model_factory is not None and not callable(model_factory):
            raise EmbeddingBackendError("model_factory must be callable")
        self._model_factory = model_factory or _default_model_factory
        self._model: object | None = None

    def load(self) -> None:
        """Load the pinned model lazily and verify its output dimension."""

        if self._model is not None:
            return
        try:
            model = self._model_factory(
                self.model_id,
                revision=self.model_revision,
                device=self.device,
            )
            eval_method = getattr(model, "eval", None)
            if not callable(eval_method):
                raise EmbeddingBackendError(
                    "loaded model does not provide eval()"
                )
            eval_method()
            dimension_method = getattr(model, "get_embedding_dimension", None)
            if not callable(dimension_method):
                dimension_method = getattr(
                    model, "get_sentence_embedding_dimension", None
                )
            if not callable(dimension_method):
                raise EmbeddingBackendError(
                    "loaded model does not expose its embedding dimension"
                )
            actual_dimension = dimension_method()
            if (
                isinstance(actual_dimension, bool)
                or not isinstance(actual_dimension, int)
            ):
                raise EmbeddingBackendError(
                    "loaded model returned an invalid embedding dimension"
                )
            if actual_dimension != self.dimension:
                raise EmbeddingBackendError(
                    "model embedding dimension mismatch: "
                    f"expected {self.dimension}, got {actual_dimension}"
                )
        except EmbeddingBackendError:
            raise
        except Exception as exc:
            raise EmbeddingBackendError(
                f"cannot load local embedding model {self.model_id!r}: {exc}"
            ) from exc
        self._model = model

    @property
    def embedding_dimension(self) -> int:
        self.load()
        return self.dimension

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Return unnormalized JSON-safe vectors for an input text list."""

        if not isinstance(texts, list) or any(
            not isinstance(text, str) for text in texts
        ):
            raise EmbeddingBackendError("texts must be a list of strings")
        if not texts:
            return []

        self.load()
        assert self._model is not None
        input_texts = list(texts)
        encode = getattr(self._model, "encode", None)
        if not callable(encode):
            raise EmbeddingBackendError("loaded model does not provide encode()")
        try:
            raw_vectors = encode(
                input_texts,
                batch_size=self.batch_size,
                show_progress_bar=self.show_progress_bar,
                convert_to_numpy=True,
                convert_to_tensor=False,
                device=self.device,
                normalize_embeddings=False,
            )
            converted = _to_plain_sequence(raw_vectors)
        except Exception as exc:
            raise EmbeddingBackendError(
                f"local embedding inference failed: {exc}"
            ) from exc

        if not _is_sequence(converted):
            raise EmbeddingBackendError(
                "embedding output must be a sequence of vectors"
            )
        assert isinstance(converted, Sequence)
        if len(converted) != len(texts):
            raise EmbeddingBackendError(
                "embedding output count mismatch: "
                f"expected {len(texts)}, got {len(converted)}"
            )

        vectors: list[list[float]] = []
        for vector_index, raw_vector in enumerate(converted):
            vector = _to_plain_sequence(raw_vector)
            if not _is_sequence(vector):
                raise EmbeddingBackendError(
                    f"embedding output[{vector_index}] must be a vector sequence"
                )
            assert isinstance(vector, Sequence)
            if len(vector) != self.dimension:
                raise EmbeddingBackendError(
                    f"embedding output[{vector_index}] dimension mismatch: "
                    f"expected {self.dimension}, got {len(vector)}"
                )

            numbers: list[float] = []
            for value_index, value in enumerate(vector):
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise EmbeddingBackendError(
                        f"embedding output[{vector_index}][{value_index}] "
                        "must be a finite JSON number"
                    )
                try:
                    number = float(value)
                except (OverflowError, TypeError, ValueError) as exc:
                    raise EmbeddingBackendError(
                        f"embedding output[{vector_index}][{value_index}] "
                        "must be a finite JSON number"
                    ) from exc
                if not math.isfinite(number):
                    raise EmbeddingBackendError(
                        f"embedding output[{vector_index}][{value_index}] "
                        "must be a finite JSON number"
                    )
                numbers.append(number)
            vectors.append(numbers)
        return vectors

    def __call__(self, texts: list[str]) -> list[list[float]]:
        return self.embed_documents(texts)


__all__ = (
    "EmbeddingBackendError",
    "SentenceTransformerEmbeddingBackend",
)
