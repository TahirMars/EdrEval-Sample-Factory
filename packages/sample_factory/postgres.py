"""PostgreSQL combo_state schema 与 DB-API 租约适配器。

连接由部署层注入（例如 ``psycopg.connect``）；核心包不持 DSN/凭据，也不新增
隐式数据库依赖。所有抢占和提交都是数据库侧条件更新。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, cast
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

POSTGRES_DDL = """
CREATE TABLE IF NOT EXISTS combo_state (
  record_id UUID PRIMARY KEY,
  combo_digest TEXT NOT NULL,
  ph_sequence JSONB NOT NULL,
  parameters_canonical JSONB NOT NULL,
  profile_id TEXT NOT NULL,
  env_detail JSONB,
  toolchain_fp TEXT,
  artifact_sha256 TEXT,
  git_manifest_ref TEXT,
  worker_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('IN_PROGRESS','SUCCESS','FAILURE')),
  failure_taxonomy TEXT CHECK (failure_taxonomy IS NULL OR failure_taxonomy IN
    ('COMPILE_FAIL','RUNTIME_CRASH','TELEMETRY_MISS','LOADER_FAIL',
     'SANDBOX_BLOCKED','TIMEOUT','ANTI_ANALYSIS_SKIP')),
  detection_outcome JSONB,
  parent_id UUID,
  seed BIGINT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  lease_expires_at TIMESTAMPTZ,
  UNIQUE (combo_digest, profile_id),
  CHECK ((status = 'FAILURE') = (failure_taxonomy IS NOT NULL)),
  CHECK (status <> 'SUCCESS' OR
    (artifact_sha256 IS NOT NULL AND toolchain_fp IS NOT NULL AND git_manifest_ref IS NOT NULL))
);
""".strip()

ConnectionFactory = Callable[[], Any]


class PostgresComboStateStore:
    """最小 DB-API 适配器；用 worker_id 条件更新实现 fencing。"""

    def __init__(self, connect: ConnectionFactory) -> None:
        self._connect = connect

    def initialize(self) -> None:
        self._execute_write(POSTGRES_DDL, ())

    def claim(self, intent: ComboIntent, *, worker_id: str, ttl: timedelta) -> LeaseClaim:
        if not worker_id or ttl <= timedelta(0):
            raise ValueError("worker_id 非空且 ttl 必须大于 0")
        record_id = str(uuid4())
        seconds = ttl.total_seconds()
        inserted = self._fetchone_write(
            """
            INSERT INTO combo_state (
              record_id, combo_digest, ph_sequence, parameters_canonical, profile_id,
              env_detail, worker_id, status, parent_id, seed, created_at, updated_at,
              lease_expires_at
            ) VALUES (
              %s, %s, %s::jsonb, %s::jsonb, %s, %s::jsonb, %s, 'IN_PROGRESS', %s, %s,
              now(), now(), now() + (%s * interval '1 second')
            )
            ON CONFLICT (combo_digest, profile_id) DO NOTHING
            RETURNING record_id::text, status, worker_id, lease_expires_at
            """,
            (
                record_id,
                intent.combo_digest,
                json.dumps(intent.ph_sequence, ensure_ascii=False),
                json.dumps(intent.parameters_canonical, ensure_ascii=False),
                intent.profile_id,
                json.dumps(intent.env_detail, ensure_ascii=False),
                worker_id,
                intent.parent_id,
                intent.seed,
                seconds,
            ),
        )
        if inserted is not None:
            return self._claim_row(inserted, LeaseDisposition.ACQUIRED)

        taken = self._fetchone_write(
            """
            UPDATE combo_state
               SET worker_id=%s,
                   lease_expires_at=now() + (%s * interval '1 second'),
                   updated_at=now()
             WHERE combo_digest=%s AND profile_id=%s
               AND status='IN_PROGRESS' AND lease_expires_at < now()
            RETURNING record_id::text, status, worker_id, lease_expires_at
            """,
            (worker_id, seconds, intent.combo_digest, intent.profile_id),
        )
        if taken is not None:
            return self._claim_row(taken, LeaseDisposition.TAKEN_OVER)

        existing = self._fetchone_read(
            """
            SELECT record_id::text, status, worker_id, lease_expires_at
              FROM combo_state WHERE combo_digest=%s AND profile_id=%s
            """,
            (intent.combo_digest, intent.profile_id),
        )
        if existing is None:  # 极窄删除竞态；表正常只追加，不应发生
            raise RuntimeError("combo_state 冲突记录在查询前消失")
        disposition = (
            LeaseDisposition.BUSY
            if str(existing[1]) == ComboStatus.IN_PROGRESS.value
            else LeaseDisposition.TERMINAL
        )
        return self._claim_row(existing, disposition)

    def heartbeat(self, record_id: str, *, worker_id: str, ttl: timedelta) -> datetime:
        if not worker_id or ttl <= timedelta(0):
            raise ValueError("worker_id 非空且 ttl 必须大于 0")
        row = self._fetchone_write(
            """
            UPDATE combo_state
               SET lease_expires_at=now() + (%s * interval '1 second'), updated_at=now()
             WHERE record_id=%s AND worker_id=%s AND status='IN_PROGRESS'
            RETURNING lease_expires_at
            """,
            (ttl.total_seconds(), record_id, worker_id),
        )
        if row is None:
            raise LeaseLostError("heartbeat 失败：租约已终结或被接管")
        return cast(datetime, row[0])

    def complete_success(
        self,
        record_id: str,
        *,
        worker_id: str,
        toolchain_fp: str,
        artifact_sha256: str,
        git_manifest_ref: str,
    ) -> ComboRecord:
        if (
            not toolchain_fp
            or not git_manifest_ref
            or len(artifact_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in artifact_sha256)
        ):
            raise ValueError("SUCCESS 三指纹不完整或 artifact_sha256 非法")
        row = self._fetchone_write(
            """
            UPDATE combo_state
               SET status='SUCCESS', toolchain_fp=%s, artifact_sha256=%s,
                   git_manifest_ref=%s, failure_taxonomy=NULL,
                   lease_expires_at=NULL, updated_at=now()
             WHERE record_id=%s AND worker_id=%s AND status='IN_PROGRESS'
            RETURNING *
            """,
            (toolchain_fp, artifact_sha256, git_manifest_ref, record_id, worker_id),
        )
        return self._required_record(row)

    def complete_failure(
        self,
        record_id: str,
        *,
        worker_id: str,
        taxonomy: FailureTaxonomy,
    ) -> ComboRecord:
        row = self._fetchone_write(
            """
            UPDATE combo_state
               SET status='FAILURE', failure_taxonomy=%s,
                   lease_expires_at=NULL, updated_at=now()
             WHERE record_id=%s AND worker_id=%s AND status='IN_PROGRESS'
            RETURNING *
            """,
            (taxonomy.value, record_id, worker_id),
        )
        return self._required_record(row)

    def write_detection(self, record_id: str, outcome: DetectionOutcome) -> ComboRecord:
        row = self._fetchone_write(
            """
            UPDATE combo_state SET detection_outcome=%s::jsonb, updated_at=now()
             WHERE record_id=%s AND status='SUCCESS' AND detection_outcome IS NULL
            RETURNING *
            """,
            (outcome.model_dump_json(), record_id),
        )
        if row is None:
            existing = self.get(record_id)
            if existing is not None and existing.detection_outcome == outcome:
                return existing
            if existing is not None and existing.detection_outcome is not None:
                raise ValueError("detection_outcome 已存在；不得覆盖检测真值")
            raise ValueError("仅 SUCCESS 记录允许 detection_outcome 回写")
        return self._record_from_row(row)

    def get(self, record_id: str) -> ComboRecord | None:
        row = self._fetchone_read("SELECT * FROM combo_state WHERE record_id=%s", (record_id,))
        return None if row is None else self._record_from_row(row)

    def _required_record(self, row: tuple[Any, ...] | None) -> ComboRecord:
        if row is None:
            raise LeaseLostError("提交失败：租约已终结或被其他 worker 接管")
        return self._record_from_row(row)

    @staticmethod
    def _record_from_row(row: tuple[Any, ...]) -> ComboRecord:
        # 顺序与 POSTGRES_DDL 保持一致；JSONB 驱动通常返回原生对象。
        detection = row[12]
        return ComboRecord(
            record_id=str(row[0]),
            combo_digest=str(row[1]),
            ph_sequence=tuple(row[2]),
            parameters_canonical=dict(row[3]),
            profile_id=str(row[4]),
            env_detail=dict(row[5] or {}),
            toolchain_fp=row[6],
            artifact_sha256=row[7],
            git_manifest_ref=row[8],
            worker_id=row[9],
            status=ComboStatus(str(row[10])),
            failure_taxonomy=None if row[11] is None else FailureTaxonomy(str(row[11])),
            detection_outcome=None
            if detection is None
            else DetectionOutcome.model_validate(detection),
            parent_id=None if row[13] is None else str(row[13]),
            seed=row[14],
            created_at=row[15],
            updated_at=row[16],
            lease_expires_at=row[17],
        )

    @staticmethod
    def _claim_row(row: tuple[Any, ...], disposition: LeaseDisposition) -> LeaseClaim:
        return LeaseClaim(
            record_id=str(row[0]),
            disposition=disposition,
            status=ComboStatus(str(row[1])),
            worker_id=None if row[2] is None else str(row[2]),
            lease_expires_at=cast(datetime | None, row[3]),
        )

    def _execute_write(self, sql: str, params: tuple[Any, ...]) -> None:
        self._run(sql, params, fetch=False, write=True)

    def _fetchone_write(self, sql: str, params: tuple[Any, ...]) -> tuple[Any, ...] | None:
        return self._run(sql, params, fetch=True, write=True)

    def _fetchone_read(self, sql: str, params: tuple[Any, ...]) -> tuple[Any, ...] | None:
        return self._run(sql, params, fetch=True, write=False)

    def _run(
        self,
        sql: str,
        params: tuple[Any, ...],
        *,
        fetch: bool,
        write: bool,
    ) -> tuple[Any, ...] | None:
        connection = self._connect()
        cursor = connection.cursor()
        try:
            cursor.execute(sql, params)
            row = cursor.fetchone() if fetch else None
            if write:
                connection.commit()
            return None if row is None else tuple(row)
        except Exception:
            if write:
                connection.rollback()
            raise
        finally:
            cursor.close()
            connection.close()


__all__ = ["ConnectionFactory", "POSTGRES_DDL", "PostgresComboStateStore"]
