"""组合公共状态表端口与租约语义参考实现。"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from packages.sample_factory.errors import LeaseLostError
from packages.sample_factory.models import (
    ComboIntent,
    ComboRecord,
    ComboStatus,
    DetectionOutcome,
    FailureTaxonomy,
    LeaseClaim,
    LeaseDisposition,
)

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("租约时钟必须是 timezone-aware datetime")


class ComboStateStore(Protocol):
    """PostgreSQL/测试实现共同遵循的 fenced-lease 接口。"""

    def claim(self, intent: ComboIntent, *, worker_id: str, ttl: timedelta) -> LeaseClaim: ...

    def heartbeat(self, record_id: str, *, worker_id: str, ttl: timedelta) -> datetime: ...

    def complete_success(
        self,
        record_id: str,
        *,
        worker_id: str,
        toolchain_fp: str,
        artifact_sha256: str,
        git_manifest_ref: str,
    ) -> ComboRecord: ...

    def complete_failure(
        self,
        record_id: str,
        *,
        worker_id: str,
        taxonomy: FailureTaxonomy,
    ) -> ComboRecord: ...

    def write_detection(self, record_id: str, outcome: DetectionOutcome) -> ComboRecord: ...

    def get(self, record_id: str) -> ComboRecord | None: ...


class InMemoryComboStateStore:
    """进程安全的语义参考实现；生产共享状态使用 PostgreSQL 适配器。"""

    def __init__(self, *, clock: Clock = _utc_now) -> None:
        self._clock = clock
        self._records: dict[str, ComboRecord] = {}
        self._identity: dict[tuple[str, str], str] = {}
        self._lock = threading.RLock()

    def _now(self) -> datetime:
        now = self._clock()
        _require_aware(now)
        return now

    @staticmethod
    def _check_claim_args(worker_id: str, ttl: timedelta) -> None:
        if not worker_id.strip():
            raise ValueError("worker_id 不得为空")
        if ttl <= timedelta(0):
            raise ValueError("lease ttl 必须大于 0")

    def claim(self, intent: ComboIntent, *, worker_id: str, ttl: timedelta) -> LeaseClaim:
        self._check_claim_args(worker_id, ttl)
        now = self._now()
        key = (intent.combo_digest, intent.profile_id)
        with self._lock:
            record_id = self._identity.get(key)
            if record_id is None:
                record_id = str(uuid4())
                expires = now + ttl
                record = ComboRecord(
                    record_id=record_id,
                    combo_digest=intent.combo_digest,
                    ph_sequence=intent.ph_sequence,
                    parameters_canonical=intent.parameters_canonical,
                    profile_id=intent.profile_id,
                    env_detail=intent.env_detail,
                    parent_id=intent.parent_id,
                    seed=intent.seed,
                    worker_id=worker_id,
                    status=ComboStatus.IN_PROGRESS,
                    created_at=now,
                    updated_at=now,
                    lease_expires_at=expires,
                )
                self._records[record_id] = record
                self._identity[key] = record_id
                return self._claim_from(record, LeaseDisposition.ACQUIRED)

            record = self._records[record_id]
            if record.status is not ComboStatus.IN_PROGRESS:
                return self._claim_from(record, LeaseDisposition.TERMINAL)
            if record.lease_expires_at is not None and not (record.lease_expires_at < now):
                return self._claim_from(record, LeaseDisposition.BUSY)

            taken = record.model_copy(
                update={
                    "worker_id": worker_id,
                    "lease_expires_at": now + ttl,
                    "updated_at": now,
                }
            )
            self._records[record_id] = taken
            return self._claim_from(taken, LeaseDisposition.TAKEN_OVER)

    def heartbeat(self, record_id: str, *, worker_id: str, ttl: timedelta) -> datetime:
        self._check_claim_args(worker_id, ttl)
        now = self._now()
        with self._lock:
            record = self._owned_in_progress(record_id, worker_id)
            expires = now + ttl
            self._records[record_id] = record.model_copy(
                update={"lease_expires_at": expires, "updated_at": now}
            )
            return expires

    def complete_success(
        self,
        record_id: str,
        *,
        worker_id: str,
        toolchain_fp: str,
        artifact_sha256: str,
        git_manifest_ref: str,
    ) -> ComboRecord:
        if not toolchain_fp or not git_manifest_ref:
            raise ValueError("SUCCESS 必须携带 toolchain_fp 与 git_manifest_ref")
        now = self._now()
        with self._lock:
            record = self._owned_in_progress(record_id, worker_id)
            completed = record.model_copy(
                update={
                    "toolchain_fp": toolchain_fp,
                    "artifact_sha256": artifact_sha256,
                    "git_manifest_ref": git_manifest_ref,
                    "status": ComboStatus.SUCCESS,
                    "failure_taxonomy": None,
                    "lease_expires_at": None,
                    "updated_at": now,
                }
            )
            # ComboRecord 不是重新校验 model_copy update；显式触发完整字段验证。
            completed = ComboRecord.model_validate(completed.model_dump())
            self._records[record_id] = completed
            return completed

    def complete_failure(
        self,
        record_id: str,
        *,
        worker_id: str,
        taxonomy: FailureTaxonomy,
    ) -> ComboRecord:
        now = self._now()
        with self._lock:
            record = self._owned_in_progress(record_id, worker_id)
            completed = record.model_copy(
                update={
                    "status": ComboStatus.FAILURE,
                    "failure_taxonomy": taxonomy,
                    "lease_expires_at": None,
                    "updated_at": now,
                }
            )
            self._records[record_id] = completed
            return completed

    def write_detection(self, record_id: str, outcome: DetectionOutcome) -> ComboRecord:
        now = self._now()
        with self._lock:
            try:
                record = self._records[record_id]
            except KeyError as exc:
                raise KeyError(f"record_id 不存在：{record_id}") from exc
            if record.status is not ComboStatus.SUCCESS:
                raise ValueError("流水线 B 只能向 A 侧 SUCCESS 记录回写检测结果")
            if record.detection_outcome is not None:
                if record.detection_outcome == outcome:
                    return record
                raise ValueError("detection_outcome 已存在；检测真值只允许幂等回写，不得覆盖")
            updated = record.model_copy(update={"detection_outcome": outcome, "updated_at": now})
            self._records[record_id] = updated
            return updated

    def get(self, record_id: str) -> ComboRecord | None:
        with self._lock:
            return self._records.get(record_id)

    def records(self) -> tuple[ComboRecord, ...]:
        with self._lock:
            return tuple(self._records.values())

    def _owned_in_progress(self, record_id: str, worker_id: str) -> ComboRecord:
        try:
            record = self._records[record_id]
        except KeyError as exc:
            raise LeaseLostError(f"record_id 不存在：{record_id}") from exc
        if record.status is not ComboStatus.IN_PROGRESS or record.worker_id != worker_id:
            raise LeaseLostError("租约已终结或被其他 worker 接管；本次结果必须丢弃")
        return record

    @staticmethod
    def _claim_from(record: ComboRecord, disposition: LeaseDisposition) -> LeaseClaim:
        return LeaseClaim(
            record_id=record.record_id,
            disposition=disposition,
            status=record.status,
            worker_id=record.worker_id,
            lease_expires_at=record.lease_expires_at,
        )


__all__ = ["Clock", "ComboStateStore", "InMemoryComboStateStore"]
