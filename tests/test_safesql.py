import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from safesql.db import Database
from safesql.guard import Rejected, check
from safesql.policy import Policy
from safesql.redteam import CASES, outcome

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "chinook.sqlite"
pytestmark = pytest.mark.skipif(not DB.exists(), reason="run: curl -sSfL -o data/chinook.sqlite <chinook url> (see README)")


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    audit = tmp_path_factory.mktemp("a") / "audit.jsonl"
    return Database(DB, Policy.load(ROOT / "policy.chinook.json"), audit)


@pytest.mark.parametrize("cat,expected,sql", CASES, ids=[f"{c}-{i}" for i, (c, _, _) in enumerate(CASES)])
def test_redteam_case(db, cat, expected, sql):
    assert outcome(db, sql) == expected


def test_limit_is_injected_and_capped():
    p = Policy(allowed_tables=frozenset({"track"}), max_rows=50)
    assert check("SELECT Name FROM Track", p).sql.endswith("LIMIT 50")
    assert check("SELECT Name FROM Track LIMIT 10", p).sql.endswith("LIMIT 10")
    assert check("SELECT Name FROM Track LIMIT 999", p).sql.endswith("LIMIT 50")


def test_connection_is_read_only_even_if_the_guard_were_bypassed(db):
    with pytest.raises(sqlite3.OperationalError):
        db.conn.execute("DELETE FROM Album")


def test_audit_log_records_every_decision(db):
    db.query("SELECT Name FROM Artist LIMIT 1")
    with pytest.raises(Rejected):
        db.query("DROP TABLE Album")
    events = [json.loads(l) for l in open(db.audit_path)]
    decisions = {e["decision"] for e in events}
    assert {"allowed", "rejected"} <= decisions
    assert any("DROP" in (e.get("reason") or "") for e in events)


def test_describe_marks_restricted_columns(db):
    cols = {c["column"]: c["restricted"] for c in db.describe("Customer")}
    assert cols["Email"] is True and cols["FirstName"] is False
    with pytest.raises(Rejected):
        db.describe("Employee")


def test_mcp_server_exposes_tools_and_refuses_with_reason(db):
    from safesql.server import build

    server = build(db)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == {"list_tables", "describe_table", "run_query"}
    ok = asyncio.run(server.call_tool("run_query", {"sql": "SELECT Name FROM Genre ORDER BY Name LIMIT 2"}))
    assert not ok.is_error and "Alternative" in json.dumps(ok.model_dump(mode="json"))
    from mcp.server.mcpserver.exceptions import ToolError
    with pytest.raises(ToolError, match="restricted"):  # the protocol layer turns this into an is_error result
        asyncio.run(server.call_tool("run_query", {"sql": "SELECT Email FROM Customer"}))
