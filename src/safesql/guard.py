"""Static checks on agent-written SQL before it reaches the database.

Layered on purpose: this parser-level check is the first line, the read-only
connection (see db.py) is the second, and the per-query time budget is the third.
A bypass of one layer should still hit the next.
"""
import logging
from dataclasses import dataclass

import sqlglot
from sqlglot import exp

from .policy import Policy

# Node types that must never appear anywhere in the tree, including inside a CTE or subquery.
FORBIDDEN = (exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Create, exp.Drop, exp.Alter,
             exp.Command, exp.Pragma, exp.Attach, exp.Detach, exp.TruncateTable, exp.Set, exp.Transaction,
             exp.Commit, exp.Rollback, exp.Into)
logging.getLogger("sqlglot").setLevel(logging.ERROR)  # unsupported syntax becomes a Command, which we reject anyway
FORBIDDEN_FUNCS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer", "randomblob", "zeroblob", "sqlite_version"}


class Rejected(Exception):
    pass


@dataclass(frozen=True)
class Checked:
    sql: str                 # the SQL that will actually run (LIMIT enforced)
    tables: tuple[str, ...]


def check(sql: str, policy: Policy) -> Checked:
    if not sql or not sql.strip():
        raise Rejected("empty query")
    if len(sql) > 20_000:
        raise Rejected("query too long")
    try:
        statements = [s for s in sqlglot.parse(sql, read="sqlite") if s is not None]
    except sqlglot.errors.ParseError as e:
        raise Rejected(f"could not parse SQL: {str(e).splitlines()[0]}") from None
    if len(statements) != 1:
        raise Rejected("exactly one statement is allowed")
    tree = statements[0]
    if not isinstance(tree, exp.Query):
        raise Rejected(f"only SELECT queries are allowed (got {tree.key.upper()})")
    for node in tree.walk():
        if isinstance(node, FORBIDDEN):
            raise Rejected(f"{node.key.upper()} is not allowed")
        if isinstance(node, exp.Func):
            name = (node.name if isinstance(node, exp.Anonymous) else node.sql_name()).lower()
            if name in FORBIDDEN_FUNCS:
                raise Rejected(f"function {name}() is not allowed")
    cte_names = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
    tables = []
    alias_to_table = {}
    for t in tree.find_all(exp.Table):
        name = t.name.lower()
        if name in cte_names:
            continue
        if t.args.get("db") or t.args.get("catalog"):
            raise Rejected("schema-qualified table names are not allowed")
        if name not in policy.allowed_tables:
            raise Rejected(f"table '{t.name}' is not allowed")
        tables.append(name)
        alias_to_table[(t.alias or t.name).lower()] = name
    if not tables and not cte_names:
        raise Rejected("query must read from an allowed table")
    _check_columns(tree, policy, alias_to_table, tables)
    return Checked(_enforce_limit(tree, policy.max_rows), tuple(sorted(set(tables))))


def _check_columns(tree, policy: Policy, alias_to_table: dict, tables: list[str]):
    # COUNT(*) is fine; a * that projects columns (SELECT *, t.*) would bypass the column denylist.
    if not policy.allow_star and any(not isinstance(s.parent, exp.Count) for s in tree.find_all(exp.Star)):
        raise Rejected("SELECT * is not allowed; name the columns (some columns are restricted)")
    if not policy.denied_columns:
        return
    for col in tree.find_all(exp.Column):
        cname = col.name.lower()
        owner = col.table.lower() if col.table else None
        candidates = [alias_to_table.get(owner, owner)] if owner else tables
        for t in candidates:
            if f"{t}.{cname}" in policy.denied_columns:
                raise Rejected(f"column '{t}.{cname}' is restricted")


def _enforce_limit(tree, max_rows: int) -> str:
    limit = tree.args.get("limit")
    if isinstance(limit, exp.Limit):
        try:
            n = int(limit.expression.this)
        except (AttributeError, TypeError, ValueError):
            raise Rejected("LIMIT must be a non-negative number") from None
        if n < 0 or n > max_rows:  # SQLite treats a negative LIMIT as 'no limit'
            tree = tree.limit(max_rows, copy=True)
    else:
        tree = tree.limit(max_rows, copy=True)
    return tree.sql(dialect="sqlite")
