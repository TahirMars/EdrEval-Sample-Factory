from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from packages.contract_gap import ContractGapError
from packages.factory_host import postgres_state as postgres_state_mod
from packages.factory_host.postgres_state import (
    create_postgres_state_backend,
    reset_postgres_state_backend_for_tests,
    resolve_factory_postgres_dsn,
)


class ResolveFactoryPostgresDsnTest(unittest.TestCase):
    def tearDown(self) -> None:
        reset_postgres_state_backend_for_tests()

    def test_literal_env_wins(self) -> None:
        dsn = resolve_factory_postgres_dsn(
            environ={"FACTORY_POSTGRES_DSN": " postgresql://u:p@localhost/db "}
        )
        self.assertEqual(dsn, "postgresql://u:p@localhost/db")

    def test_dsn_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dsn"
            path.write_text("postgresql://file@localhost/db\n", encoding="utf-8")
            dsn = resolve_factory_postgres_dsn(
                environ={"FACTORY_POSTGRES_DSN_FILE": str(path)}
            )
            self.assertEqual(dsn, "postgresql://file@localhost/db")

    def test_missing_file_is_contract_gap(self) -> None:
        with self.assertRaises(ContractGapError):
            resolve_factory_postgres_dsn(
                environ={"FACTORY_POSTGRES_DSN_FILE": "Z:/no-such-dsn-file"}
            )

    def test_secret_store_uri(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = root / "secrets"
            (store / "db").mkdir(parents=True)
            (store / "db" / "factory-combo-dsn").write_text(
                "postgresql://secret@localhost/db\n", encoding="utf-8"
            )
            secrets_env = root / "secrets.env"
            secrets_env.write_text(
                f"SECRET_STORE_DIR={store.as_posix()}\nLLM_API_KEY=x\n",
                encoding="utf-8",
            )
            dsn = resolve_factory_postgres_dsn(
                environ={},
                secrets_env_path=secrets_env,
            )
            self.assertEqual(dsn, "postgresql://secret@localhost/db")

    def test_create_backend_initializes_with_injected_connect(self) -> None:
        reset_postgres_state_backend_for_tests()
        connection = MagicMock()
        cursor = MagicMock()
        connection.cursor.return_value = cursor
        cursor.fetchone.return_value = None

        def connect():
            return connection

        store = create_postgres_state_backend(
            environ={"FACTORY_POSTGRES_DSN": "postgresql://test@localhost/db"},
            connect=connect,
        )
        self.assertIsNotNone(store)
        self.assertTrue(any("CREATE TABLE" in sql for sql, _ in [
            (call.args[0], call.args[1]) for call in cursor.execute.call_args_list
        ]))
        connection.commit.assert_called()


if __name__ == "__main__":
    unittest.main()
