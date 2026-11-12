"""What the agent may read. Loaded from JSON so a deployment changes policy without code."""
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Policy:
    allowed_tables: frozenset[str]                       # lower-case table names the agent may read
    denied_columns: frozenset[str] = frozenset()         # "table.column", lower-case; never returned
    max_rows: int = 200
    timeout_ms: int = 2000
    allow_star: bool = False                             # SELECT * would bypass the column denylist

    @classmethod
    def load(cls, path: Path) -> "Policy":
        d = json.loads(Path(path).read_text())
        return cls(
            allowed_tables=frozenset(t.lower() for t in d["allowed_tables"]),
            denied_columns=frozenset(c.lower() for c in d.get("denied_columns", [])),
            max_rows=int(d.get("max_rows", 200)), timeout_ms=int(d.get("timeout_ms", 2000)),
            allow_star=bool(d.get("allow_star", False)),
        )
