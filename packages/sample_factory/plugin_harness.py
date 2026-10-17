"""Evidence-backed Plugin Harness contracts for system-telemetry self-tests.

The harness boundary deliberately accepts Sysmon/CAPE-style system telemetry only.
EDR/Sigma detection belongs to the separate detection-evaluation pipeline and is
never required to produce ``behavior_valid`` here.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

from packages.sample_factory.errors import CatalogError, VerificationError
from packages.sample_factory.models import AtomRole
from packages.sample_factory.plugin_models import (
    PluginBuildResult,
    PluginRequest,
    PluginSourceCandidate,
    PluginValidationResult,
)

_SHA256_RE = r"^[a-f0-9]{64}$"
_PLUGIN_RUN_RE = r"^plugin-run-[a-z0-9-]{8,79}$"
_HARNESS_REF_RE = r"^plugin-harness://.+"


class HarnessTelemetrySource(StrEnum):
    """Telemetry sources allowed for plugin self-validation."""

    SYSMON = "sysmon"
    CAPE = "cape"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PluginHarnessSpec(_FrozenModel):
    """Operator-owned, versioned contract for one role-specific harness."""

    schema_version: Literal["sf-plugin-harness-v1"] = "sf-plugin-harness-v1"
    harness_ref: str = Field(pattern=_HARNESS_REF_RE)
    role: AtomRole
    ph_ids: tuple[str, ...] = ()
    profile_ids: tuple[str, ...] = Field(min_length=1)
    architectures: tuple[Literal["x86", "x64", "any"], ...] = Field(min_length=1)
    telemetry_sources: tuple[HarnessTelemetrySource, ...] = Field(min_length=1)
    input_contract_ref: str = Field(min_length=1)
    oracle_ref: str = Field(min_length=1)
    collector_config_ref: str = Field(min_length=1)
    isolation_profile_ref: str = Field(min_length=1)
    required_assertions: tuple[str, ...] = Field(min_length=1)
    timeout_s: float = Field(default=300, gt=0)

    @model_validator(mode="after")
    def _unique_contract_values(self) -> PluginHarnessSpec:
        if len(self.profile_ids) != len(set(self.profile_ids)):
            raise ValueError("HarnessSpec.profile_ids must be unique")
        if len(self.architectures) != len(set(self.architectures)):
            raise ValueError("HarnessSpec.architectures must be unique")
        if len(self.telemetry_sources) != len(set(self.telemetry_sources)):
            raise ValueError("HarnessSpec.telemetry_sources must be unique")
        if len(self.required_assertions) != len(set(self.required_assertions)):
            raise ValueError("HarnessSpec.required_assertions must be unique")
        if len(self.ph_ids) != len(set(self.ph_ids)):
            raise ValueError("HarnessSpec.ph_ids must be unique")
        return self


class JsonPluginHarnessCatalog:
    """Load operator-owned HarnessSpec records without accepting model-defined runners."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def load(self) -> dict[str, PluginHarnessSpec]:
        if not self._path.is_file():
            raise CatalogError(f"plugin harness catalog does not exist: {self._path}")
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            values = raw["harnesses"] if isinstance(raw, dict) else raw
            if not isinstance(values, list):
                raise TypeError("top-level harnesses must be an array")
            specs = [PluginHarnessSpec.model_validate(value) for value in values]
        except Exception as exc:
            if isinstance(exc, CatalogError):
                raise
            raise CatalogError(f"plugin harness catalog is invalid: {self._path}") from exc
        result = {spec.harness_ref: spec for spec in specs}
        if len(result) != len(specs):
            raise CatalogError("plugin harness harness_ref must be unique")
        return result

    def get(self, harness_ref: str) -> PluginHarnessSpec:
        try:
            return self.load()[harness_ref]
        except KeyError as exc:
            raise CatalogError(f"plugin harness is not registered: {harness_ref}") from exc


class HarnessAssertion(_FrozenModel):
    """One deterministic assertion backed by an immutable system evidence ref."""

    assertion_id: str = Field(min_length=1)
    passed: bool = Field(strict=True)
    required: bool = Field(default=True, strict=True)
    evidence_ref: str = Field(min_length=1)


class PluginHarnessObservation(_FrozenModel):
    """Execution and system-telemetry evidence returned by an operator runner."""

    schema_version: Literal["sf-plugin-harness-observation-v1"] = (
        "sf-plugin-harness-observation-v1"
    )
    harness_ref: str = Field(pattern=_HARNESS_REF_RE)
    plugin_run_id: str = Field(pattern=_PLUGIN_RUN_RE)
    profile_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    process_identity: str = Field(min_length=1)
    isolation_profile_ref: str = Field(min_length=1)
    collector_config_ref: str = Field(min_length=1)
    artifact_sha256: str = Field(pattern=_SHA256_RE)
    source_digest: str = Field(pattern=_SHA256_RE)
    telemetry_source: HarnessTelemetrySource
    started_at: datetime
    finished_at: datetime
    contract_valid: bool = Field(strict=True)
    atom_valid: bool = Field(strict=True)
    assertions: tuple[HarnessAssertion, ...] = Field(min_length=1)
    evidence_ref: str = Field(min_length=1)

    @model_validator(mode="after")
    def _observation_integrity(self) -> PluginHarnessObservation:
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise ValueError("Harness observation started_at must be timezone-aware")
        if self.finished_at.tzinfo is None or self.finished_at.utcoffset() is None:
            raise ValueError("Harness observation finished_at must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("Harness observation finished_at precedes started_at")
        ids = [item.assertion_id for item in self.assertions]
        if len(ids) != len(set(ids)):
            raise ValueError("Harness assertion_id must be unique")
        if not any(item.required for item in self.assertions):
            raise ValueError("Harness observations require at least one required assertion")
        return self

    @property
    def behavior_valid(self) -> bool:
        return self.contract_valid and self.atom_valid and all(
            item.passed for item in self.assertions if item.required
        )


class PluginHarnessExecutor(Protocol):
    """Operator-owned executor; implementations must run outside the control host."""

    def execute(
        self,
        spec: PluginHarnessSpec,
        source: PluginSourceCandidate,
        build: PluginBuildResult,
        request: PluginRequest,
        *,
        plugin_run_id: str,
    ) -> PluginHarnessObservation: ...


class PluginArtifactResolver(Protocol):
    def resolve_artifact(self, artifact_ref: str) -> Path: ...


class SystemTelemetryPluginHarness:
    """Adapt an isolated Sysmon/CAPE runner to ``PluginHarnessBackend``."""

    def __init__(
        self,
        spec: PluginHarnessSpec,
        executor: PluginHarnessExecutor,
        *,
        artifact_resolver: PluginArtifactResolver | None = None,
    ) -> None:
        self._spec = spec
        self._executor = executor
        self._artifact_resolver = artifact_resolver

    def validate(
        self,
        source: PluginSourceCandidate,
        build: PluginBuildResult,
        request: PluginRequest,
        *,
        plugin_run_id: str,
    ) -> PluginValidationResult:
        if request.harness_ref is not None and request.harness_ref != self._spec.harness_ref:
            raise VerificationError("PluginRequest harness_ref does not match HarnessSpec")
        if request.profile_id not in self._spec.profile_ids:
            raise VerificationError(
                f"HarnessSpec {self._spec.harness_ref} does not support profile={request.profile_id}"
            )
        if (
            request.intent.architecture not in self._spec.architectures
            and "any" not in self._spec.architectures
        ):
            raise VerificationError(
                f"HarnessSpec {self._spec.harness_ref} does not support architecture={request.intent.architecture}"
            )
        if request.intent.role is not self._spec.role:
            raise VerificationError("PluginRequest role does not match HarnessSpec")
        if self._spec.ph_ids and request.intent.ph_ids != self._spec.ph_ids:
            raise VerificationError("PluginRequest ph_ids do not match HarnessSpec")
        if self._artifact_resolver is not None:
            artifact = self._artifact_resolver.resolve_artifact(build.artifact_ref).resolve()
            if not artifact.is_file() or _sha256_file(artifact) != build.artifact_sha256:
                raise VerificationError("Harness artifact identity does not match PluginBuildResult")

        observation = self._executor.execute(
            self._spec,
            source,
            build,
            request,
            plugin_run_id=plugin_run_id,
        )
        self._validate_observation(observation, source, build, request, plugin_run_id)
        return PluginValidationResult(
            harness_ref=self._spec.harness_ref,
            contract_valid=observation.contract_valid,
            atom_valid=observation.atom_valid,
            behavior_valid=observation.behavior_valid,
            evidence_ref=observation.evidence_ref,
            assertions=tuple(
                f"{item.assertion_id}={'passed' if item.passed else 'failed'}:{item.evidence_ref}"
                for item in observation.assertions
            ),
        )

    def _validate_observation(
        self,
        observation: PluginHarnessObservation,
        source: PluginSourceCandidate,
        build: PluginBuildResult,
        request: PluginRequest,
        plugin_run_id: str,
    ) -> None:
        if observation.harness_ref != self._spec.harness_ref:
            raise VerificationError("Harness observation harness_ref mismatch")
        if observation.plugin_run_id != plugin_run_id:
            raise VerificationError("Harness observation plugin_run_id mismatch")
        if observation.profile_id != request.profile_id:
            raise VerificationError("Harness observation profile_id mismatch")
        if observation.isolation_profile_ref != self._spec.isolation_profile_ref:
            raise VerificationError("Harness observation isolation_profile_ref mismatch")
        if observation.collector_config_ref != self._spec.collector_config_ref:
            raise VerificationError("Harness observation collector_config_ref mismatch")
        if observation.artifact_sha256 != build.artifact_sha256:
            raise VerificationError("Harness observation artifact_sha256 mismatch")
        if observation.source_digest != source.source_digest:
            raise VerificationError("Harness observation source_digest mismatch")
        if observation.telemetry_source not in self._spec.telemetry_sources:
            raise VerificationError("Harness observation telemetry source is not in HarnessSpec")
        observed_ids = {item.assertion_id for item in observation.assertions}
        missing = sorted(set(self._spec.required_assertions) - observed_ids)
        if missing:
            raise VerificationError(
                "Harness observation is missing required assertions: " + ", ".join(missing)
            )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "HarnessAssertion",
    "HarnessTelemetrySource",
    "JsonPluginHarnessCatalog",
    "PluginArtifactResolver",
    "PluginHarnessExecutor",
    "PluginHarnessObservation",
    "PluginHarnessSpec",
    "SystemTelemetryPluginHarness",
]
