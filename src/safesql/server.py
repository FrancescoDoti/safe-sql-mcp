"""MCP server: expose the guarded database to any MCP client (Claude Desktop, Claude Code, agents).

safesql-mcp --db data/chinook.sqlite --policy policy.chinook.json [--audit audit.jsonl]
"""
import argparse
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .db import Database, TimedOut
from .guard import Rejected
from .policy import Policy


def build(db: Database) -> MCPServer:
    server = MCPServer(
        name="safe-sql",
        instructions=(
            "Read-only SQL over a business database. Call list_tables and describe_table before writing queries. "
            "Only single SELECT statements on allowed tables run; restricted columns and SELECT * are refused; "
            f"results are capped at {db.policy.max_rows} rows. If a query is refused, the error says why; fix the query rather than retrying it."
        ),
    )

    @server.tool(description="List the tables you are allowed to query.")
    def list_tables() -> list[str]:
        return db.tables()

    @server.tool(description="Columns and types of one allowed table; restricted columns are marked and cannot be selected.")
    def describe_table(table: str) -> list[dict]:
        try:
            return db.describe(table)
        except Rejected as e:
            raise ToolError(str(e)) from None

    @server.tool(description="Run one read-only SELECT query (SQLite dialect). Returns columns, rows and the SQL actually executed.")
    def run_query(sql: str) -> dict:
        try:
            return db.query(sql)
        except (Rejected, TimedOut) as e:
            # ToolError, not ValueError: the SDK hides the text of unexpected exceptions from the client,
            # and an agent that cannot see *why* it was refused just retries the same query.
            raise ToolError(f"refused: {e}") from None

    return server


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--audit", default=None)
    a = ap.parse_args(argv)
    db = Database(Path(a.db), Policy.load(Path(a.policy)), Path(a.audit) if a.audit else None)
    build(db).run("stdio")


if __name__ == "__main__":
    main()
