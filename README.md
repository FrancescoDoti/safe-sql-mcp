# safe-sql-mcp: let an AI agent query your database without trusting it

An [MCP](https://modelcontextprotocol.io) server that gives any MCP client (Claude Desktop, Claude Code, your own agent) **read-only, policy-checked** SQL access to a database. The design assumption: the SQL comes from a model that can be wrong, confused or prompt-injected, so every query is treated as hostile input.

This is the integration problem a forward-deployed engineer hits on week one: the customer wants "chat with our data", and their security team wants guarantees. Here the guarantees are enforced in code and checked by an adversarial test suite.

## Three layers, each assuming the one before it failed

| Layer | What it does | What it stops |
|---|---|---|
| **1. AST policy check** (`guard.py`, [sqlglot](https://github.com/tobymao/sqlglot)) | Parses the SQL and walks the entire tree, including CTEs and subqueries | Writes, DDL, stacked statements, PRAGMA/ATTACH, dangerous functions, tables outside the allowlist, **restricted (PII) columns referenced anywhere** (SELECT, WHERE, ORDER BY, HAVING, inside functions, inside CTEs), `SELECT *` |
| **2. Read-only connection** (`db.py`) | `mode=ro` URI plus `PRAGMA query_only` | Any write that slipped past layer 1 |
| **3. Time and row budgets** | A progress handler aborts queries past `timeout_ms`; LIMIT is injected or capped at `max_rows` | Cartesian-join bombs, recursive CTEs, accidental full-table dumps |

All of it is configured in a JSON policy ([`policy.chinook.json`](policy.chinook.json)), and every decision, allowed or refused, is appended to an audit log (`--audit audit.jsonl`):

```json
{"sql": "SELECT Email FROM Customer", "decision": "rejected", "reason": "column 'customer.email' is restricted", "ts": "..."}
```

## Red-team results

77 cases against the [Chinook](https://github.com/lerocha/chinook-database) sample database (a music store with customers, invoices and employees). The policy allows 10 tables, hides the `Employee` table entirely, and restricts 7 PII columns (email, phone, fax, addresses, postcodes).

| Category | Example | Cases | As expected |
|---|---|---|---|
| Writes / DDL | `WITH x AS (DELETE FROM Album RETURNING AlbumId) SELECT AlbumId FROM x` | 9 | 9/9 refused |
| Stacked statements | `SELECT Name FROM Artist; -- harmless⏎DELETE FROM Album` | 3 | 3/3 refused |
| Engine commands | `PRAGMA writable_schema = 1`, `ATTACH DATABASE ...` | 7 | 7/7 refused |
| Dangerous functions | `load_extension`, `readfile`, `randomblob(1e9)` | 4 | 4/4 refused |
| Out-of-policy tables | `sqlite_master`, `pragma_table_info('Customer')`, `main.Employee`, `UNION ... FROM Employee` | 9 | 9/9 refused |
| PII columns | `WHERE Email LIKE '%@gmail.com'`, `ORDER BY Address`, PII via CTE alias, `SELECT *` | 12 | 12/12 refused |
| Evasion (written *after* the guard, to probe it) | `` `Email` ``, `[Email]`, `json_each((SELECT group_concat(Email) ...))`, `HAVING max(length(Phone))` | 13 | 13/13 refused |
| Malformed | `SEL/**/ECT`, `LIMIT (SELECT 100000)` | 3 | 3/3 refused |
| Resource exhaustion | 3-way cross join of 3,503 tracks (4.3 × 10¹⁰ rows), infinite recursive CTE | 5 | timed out at 2 s, or capped at 200 rows |
| **Legitimate analytics** | joins, CTEs, window functions, `strftime`, `HAVING`, `CASE` | 12 | **12/12 run unchanged** |

Run it yourself: `python -m safesql.redteam` (about 2 s). The same cases run in `pytest`, alongside tests for the read-only connection, the audit log and the MCP tool layer.

**How the suite was built, honestly.** I wrote the first 64 cases alongside the guard. Only one didn't behave as I first expected: `LIMIT -1` (SQLite reads it as "no limit"). The guard refuses it, and I kept that stricter behaviour. The 13 evasion cases came afterwards, as attempts to break the finished guard. None got through.

## Bugs this project caught

- **`COUNT(*)` was refused** by the first version of the `SELECT *` rule. A `*` is now allowed only directly inside `COUNT`.
- **A refused query looked like a server crash to the agent.** In MCP Python SDK 2.x, a plain exception's message is hidden from the client, so the agent saw "Error executing tool run_query" with no reason, and an agent with no reason retries the same query. Refusals now raise `ToolError`, verified over real stdio by [`examples/client_demo.py`](examples/client_demo.py), whose output is `refused: column 'customer.email' is restricted`.

## Use it

```bash
uv venv && uv pip install -e '.[dev]'
curl -sSfL -o data/chinook.sqlite https://github.com/lerocha/chinook-database/releases/download/v1.4.5/Chinook_Sqlite.sqlite
pytest && python -m safesql.redteam
python examples/client_demo.py          # spawns the server over stdio and calls it as an MCP client
```

Claude Desktop / Claude Code configuration:

```json
{
  "mcpServers": {
    "safe-sql": {
      "command": "/path/to/safe-sql-mcp/.venv/bin/safesql-mcp",
      "args": ["--db", "/path/to/data/chinook.sqlite", "--policy", "/path/to/policy.chinook.json", "--audit", "/path/to/audit.jsonl"]
    }
  }
}
```

Tools exposed: `list_tables`, `describe_table` (restricted columns are marked, so the model knows not to ask for them), and `run_query`, which returns the rows plus the SQL actually executed.

## Limitations, stated plainly

- **Column- and table-level policy only, not row-level.** "Analysts may see only EMEA customers" needs row filters, which means rewriting the query with a mandatory `WHERE`. That's the next feature, and the parsed AST makes it possible.
- **Aggregates can still leak in principle.** The guard blocks any *reference* to a restricted column, but an allowed column with high cardinality, such as a customer's full name plus city, can still identify a person. Policy design matters as much as enforcement.
- **SQLite only.** The guard is dialect-aware through sqlglot, but read-only enforcement and timeouts on Postgres need a read-only role and `statement_timeout`. Those are configuration, not code here.
- **The suite is my own.** 77 cases is evidence, not proof. The layered design exists precisely because no parser check is complete.
