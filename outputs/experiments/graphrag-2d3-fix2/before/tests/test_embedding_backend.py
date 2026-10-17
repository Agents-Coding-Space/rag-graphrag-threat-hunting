from __future__ import annotations

from copy import deepcopy
import math
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

import threat_hunting.retrieval as retrieval_package
from threat_hunting.retrieval import (
    EmbeddingBackendError,
    SentenceTransformerEmbeddingBackend,
)
from threat_hunting.retrieval import embedding_backend


REVISION = "a" * 40


class ArrayLike:
    def __init__(self, value: object) -> None:
        self.value = value

    def tolist(self) -> object:
        return deepcopy(self.value)


class TensorLike(ArrayLike):
    def __init__(self, value: object) -> None:
        super().__init__(value)
        self.detached = False
        self.on_cpu = False

    def detach(self) -> TensorLike:
        self.detached = True
        return self

    def cpu(self) -> TensorLike:
        self.on_cpu = True
        return self


class FakeModel:
    def __init__(self, vectors: object, *, dimension: object = 3) -> None:
        self.vectors = vectors
        self.dimension = dimension
        self.eval_calls = 0
        self.encode_calls: list[tuple[list[str], dict[str, object]]] = []
        self.encode_error: Exception | None = None

    def eval(self) -> None:
        self.eval_calls += 1

    def get_sentence_embedding_dimension(self) -> object:
        return self.dimension

    def encode(self, texts: list[str], **kwargs: object) -> object:
        self.encode_calls.append((list(texts), dict(kwargs)))
        if self.encode_error is not None:
            raise self.encode_error
        return self.vectors


def _backend(
    model: object,
    *,
    dimension: int = 3,
    factory_calls: list[tuple[str, dict[str, object]]] | None = None,
) -> SentenceTransformerEmbeddingBackend:
    def factory(model_id: str, **kwargs: object) -> object:
        if factory_calls is not None:
            factory_calls.append((model_id, dict(kwargs)))
        return model

    return SentenceTransformerEmbeddingBackend(
        model_id="organization/generic-model",
        model_revision=REVISION,
        dimension=dimension,
        device="cpu",
        batch_size=7,
        show_progress_bar=False,
        model_factory=factory,
    )


def test_backend_and_error_are_exported() -> None:
    assert (
        retrieval_package.SentenceTransformerEmbeddingBackend
        is SentenceTransformerEmbeddingBackend
    )
    assert retrieval_package.EmbeddingBackendError is EmbeddingBackendError
    assert "SentenceTransformerEmbeddingBackend" in retrieval_package.__all__
    assert "EmbeddingBackendError" in retrieval_package.__all__


def test_model_is_lazy_loaded_with_exact_identity_and_cpu() -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    model = FakeModel([[1.0, 2.0, 3.0]])
    backend = _backend(model, factory_calls=calls)

    assert calls == []
    backend.load()
    backend.load()

    assert calls == [
        (
            "organization/generic-model",
            {"revision": REVISION, "device": "cpu"},
        )
    ]
    assert model.eval_calls == 1
    assert backend.embedding_dimension == 3


def test_backend_prefers_current_embedding_dimension_api() -> None:
    model = FakeModel([[1.0, 2.0, 3.0]])
    model.get_embedding_dimension = lambda: 3  # type: ignore[attr-defined]
    model.get_sentence_embedding_dimension = lambda: 4  # type: ignore[method-assign]

    assert _backend(model).embedding_dimension == 3


def test_encode_contract_and_input_immutability() -> None:
    model = FakeModel(ArrayLike([[1, 2.5, 3], [4, 5, 6]]))
    backend = _backend(model)
    texts = ["first", "second"]
    original = list(texts)

    result = backend.embed_documents(texts)

    assert texts == original
    assert result == [[1.0, 2.5, 3.0], [4.0, 5.0, 6.0]]
    assert model.encode_calls == [
        (
            original,
            {
                "batch_size": 7,
                "show_progress_bar": False,
                "convert_to_numpy": True,
                "convert_to_tensor": False,
                "device": "cpu",
                "normalize_embeddings": False,
            },
        )
    ]


def test_tensor_like_output_is_detached_moved_to_cpu_and_json_safe() -> None:
    output = TensorLike([[1, 2, 3]])
    result = _backend(FakeModel(output)).embed_documents(["text"])

    assert result == [[1.0, 2.0, 3.0]]
    assert output.detached is True
    assert output.on_cpu is True


def test_empty_input_does_not_load_model() -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    backend = _backend(FakeModel([]), factory_calls=calls)

    assert backend.embed_documents([]) == []
    assert calls == []


@pytest.mark.parametrize("value", [None, "text", ("tuple",)])
def test_rejects_non_list_input(value: object) -> None:
    with pytest.raises(EmbeddingBackendError, match="list of strings"):
        _backend(FakeModel([])).embed_documents(value)  # type: ignore[arg-type]


def test_rejects_non_string_item() -> None:
    with pytest.raises(EmbeddingBackendError, match="list of strings"):
        _backend(FakeModel([])).embed_documents(["ok", 1])  # type: ignore[list-item]


def test_rejects_wrong_vector_count() -> None:
    with pytest.raises(EmbeddingBackendError, match="count mismatch"):
        _backend(FakeModel([[1.0, 2.0, 3.0]])).embed_documents(["a", "b"])


def test_rejects_wrong_vector_dimension() -> None:
    with pytest.raises(EmbeddingBackendError, match="dimension mismatch"):
        _backend(FakeModel([[1.0, 2.0]])).embed_documents(["a"])


@pytest.mark.parametrize("value", [True, "1", None, math.nan, math.inf, -math.inf])
def test_rejects_non_finite_or_non_numeric_vector_values(value: object) -> None:
    with pytest.raises(EmbeddingBackendError, match="finite JSON number"):
        _backend(FakeModel([[value, 2.0, 3.0]])).embed_documents(["a"])


def test_rejects_non_sequence_output() -> None:
    with pytest.raises(EmbeddingBackendError, match="sequence of vectors"):
        _backend(FakeModel(object())).embed_documents(["a"])


def test_rejects_non_sequence_vector() -> None:
    with pytest.raises(EmbeddingBackendError, match="vector sequence"):
        _backend(FakeModel([object()])).embed_documents(["a"])


@pytest.mark.parametrize("revision", ["main", "latest", "a" * 39, "z" * 40])
def test_rejects_floating_or_invalid_model_revision(revision: str) -> None:
    with pytest.raises(EmbeddingBackendError, match="full 40-character"):
        SentenceTransformerEmbeddingBackend(
            model_id="organization/model",
            model_revision=revision,
            dimension=3,
            device="cpu",
            batch_size=1,
            show_progress_bar=False,
            model_factory=lambda *args, **kwargs: object(),
        )


def test_wraps_model_factory_exception() -> None:
    def factory(*args: object, **kwargs: object) -> object:
        raise RuntimeError("synthetic load failure")

    backend = SentenceTransformerEmbeddingBackend(
        model_id="organization/model",
        model_revision=REVISION,
        dimension=3,
        device="cpu",
        batch_size=1,
        show_progress_bar=False,
        model_factory=factory,
    )

    with pytest.raises(EmbeddingBackendError, match="cannot load") as captured:
        backend.load()
    assert isinstance(captured.value.__cause__, RuntimeError)


def test_wraps_encode_exception() -> None:
    model = FakeModel([[1.0, 2.0, 3.0]])
    model.encode_error = RuntimeError("synthetic inference failure")

    with pytest.raises(EmbeddingBackendError, match="inference failed") as captured:
        _backend(model).embed_documents(["a"])
    assert isinstance(captured.value.__cause__, RuntimeError)


@pytest.mark.parametrize("actual_dimension", [True, None, "3", 2])
def test_rejects_invalid_or_mismatched_model_dimension(
    actual_dimension: object,
) -> None:
    with pytest.raises(EmbeddingBackendError, match="embedding dimension"):
        _backend(
            FakeModel([[1.0, 2.0, 3.0]], dimension=actual_dimension)
        ).load()


def test_backend_does_not_normalize_vectors() -> None:
    result = _backend(
        FakeModel([[3.0, 4.0]], dimension=2), dimension=2
    ).embed_documents(["text"])

    assert result == [[3.0, 4.0]]


def test_default_factory_disables_hugging_face_telemetry_and_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def constructor(model_id: str, **kwargs: object) -> object:
        calls.append((model_id, dict(kwargs)))
        return object()

    monkeypatch.setitem(
        sys.modules,
        "sentence_transformers",
        SimpleNamespace(SentenceTransformer=constructor),
    )

    result = embedding_backend._default_model_factory(
        "organization/model", revision=REVISION, device="cpu"
    )

    assert result is not None
    assert calls == [
        (
            "organization/model",
            {
                "revision": REVISION,
                "device": "cpu",
                "trust_remote_code": False,
            },
        )
    ]
    assert os.environ["HF_HUB_DISABLE_TELEMETRY"] == "1"
    assert os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] == "1"
    assert os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] == "1"
    assert os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] == "1"
    assert os.environ["DO_NOT_TRACK"] == "1"


def test_generic_backend_has_no_production_scenario_or_model_hardcodes() -> None:
    source = Path(embedding_backend.__file__).read_text(encoding="utf-8").casefold()

    for forbidden in (
        "all-minilm",
        "mshta",
        "powershell",
        "retrieval_corpus.json",
        "vector_index.json",
    ):
        assert forbidden not in source
