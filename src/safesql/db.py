"""Execution layer: a read-only SQLite connection with a time budget and an audit trail."""
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from .guard import Rejected, check
from .policy import Policy


class TimedOut(Exception):
    pass


class Database:
    def __init__(self, path: Path, policy: Policy, audit_path: Path | None = None):
        # mode=ro: even a query that slipped past the guard cannot write. Second layer, not the first.
        self.conn = sqlite3.connect(f"file:{Path(path).resolve()}?mode=ro", uri=True, check_same_thread=False)
        self.conn.execute("PRAGMA query_only = ON")
        self.policy = policy
        self.audit_path = audit_path

    def _audit(self, **event):
        if self.audit_path:
            event["ts"] = datetime.now(timezone.utc).isoformat()
            with open(self.audit_path, "a") as f:
                f.write(json.dumps(event) + "\n")

    def query(self, sql: str) -> dict:
        t0 = time.perf_counter()
        try:
            checked = check(sql, self.policy)
        except Rejected as e:
            self._audit(sql=sql, decision="rejected", reason=str(e))
            raise
        deadline = t0 + self.policy.timeout_ms / 1000
        # Returning non-zero from the progress handler aborts the statement (recursive CTE bombs, huge joins).
        self.conn.set_progress_handler(lambda: int(time.perf_counter() > deadline), 10_000)
        try:
            cur = self.conn.execute(checked.sql)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchmany(self.policy.max_rows)
        except sqlite3.OperationalError as e:
            if "interrupted" in str(e):
                self._audit(sql=sql, decision="timeout")
                raise TimedOut(f"query exceeded {self.policy.timeout_ms} ms") from None
            self._audit(sql=sql, decision="error", reason=str(e))
            raise
        finally:
            self.conn.set_progress_handler(None, 0)
        ms = (time.perf_counter() - t0) * 1000
        self._audit(sql=sql, executed=checked.sql, decision="allowed", rows=len(rows), ms=round(ms, 1), tables=checked.tables)
        return {"columns": cols, "rows": rows, "row_count": len(rows), "truncated": len(rows) == self.policy.max_rows, "executed_sql": checked.sql}

    def tables(self) -> list[str]:
        names = [r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return [n for n in names if n.lower() in self.policy.allowed_tables]

    def describe(self, table: str) -> list[dict]:
        if table.lower() not in self.policy.allowed_tables or table not in self.tables():
            raise Rejected(f"table '{table}' is not allowed")
        info = self.conn.execute(f'PRAGMA table_info("{table}")').fetchall()  # name validated against the real table list above
        return [{"column": c[1], "type": c[2], "restricted": f"{table.lower()}.{c[1].lower()}" in self.policy.denied_columns} for c in info]
