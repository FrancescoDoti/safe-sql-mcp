"""Adversarial and benign queries with the expected outcome; run with python -m safesql.redteam.

Outcomes: reject (guard refuses), timeout (time budget kills it), capped (runs, but the
result hits the max_rows cap), allow (runs and returns everything it asked for).
"""
import sys
from collections import defaultdict
from pathlib import Path

CASES = [
    # --- writes and DDL ---
    ("write", "reject", "DELETE FROM Album"),
    ("write", "reject", "UPDATE Track SET UnitPrice = 0"),
    ("write", "reject", "INSERT INTO Genre (Name) VALUES ('x')"),
    ("write", "reject", "REPLACE INTO Genre (GenreId, Name) VALUES (1, 'x')"),
    ("write", "reject", "DROP TABLE Album"),
    ("write", "reject", "CREATE TABLE stolen AS SELECT Name FROM Artist"),
    ("write", "reject", "ALTER TABLE Album ADD COLUMN x TEXT"),
    ("write", "reject", "WITH x AS (DELETE FROM Album RETURNING AlbumId) SELECT AlbumId FROM x"),
    ("write", "reject", "SELECT Name INTO backup FROM Artist"),
    # --- stacked statements ---
    ("stacked", "reject", "SELECT Name FROM Artist; DROP TABLE Album"),
    ("stacked", "reject", "SELECT Name FROM Artist; -- harmless\nDELETE FROM Album"),
    ("stacked", "reject", "SELECT Name FROM Artist;;SELECT Title FROM Album"),
    # --- engine commands ---
    ("engine", "reject", "PRAGMA table_info(Employee)"),
    ("engine", "reject", "PRAGMA writable_schema = 1"),
    ("engine", "reject", "ATTACH DATABASE '/tmp/x.db' AS x"),
    ("engine", "reject", "DETACH DATABASE main"),
    ("engine", "reject", "VACUUM"),
    ("engine", "reject", "BEGIN TRANSACTION"),
    ("engine", "reject", "ANALYZE"),
    # --- dangerous functions ---
    ("function", "reject", "SELECT load_extension('/tmp/evil.so') FROM Album"),
    ("function", "reject", "SELECT readfile('/etc/passwd') FROM Album"),
    ("function", "reject", "SELECT randomblob(1000000000) FROM Album"),
    ("function", "reject", "SELECT zeroblob(1000000000) FROM Album"),
    # --- schema and out-of-policy tables ---
    ("table", "reject", "SELECT sql FROM sqlite_master"),
    ("table", "reject", "SELECT sql FROM sqlite_schema"),
    ("table", "reject", "SELECT name FROM pragma_table_info('Customer')"),
    ("table", "reject", "SELECT FirstName, Title FROM Employee"),
    ("table", "reject", "SELECT FirstName FROM eMpLoYeE"),
    ("table", "reject", 'SELECT FirstName FROM "Employee"'),
    ("table", "reject", "SELECT FirstName FROM main.Employee"),
    ("table", "reject", "SELECT Name FROM Artist UNION SELECT LastName FROM Employee"),
    ("table", "reject", "SELECT Name FROM Artist WHERE ArtistId IN (SELECT EmployeeId FROM Employee)"),
    # --- restricted (PII) columns, however they are reached ---
    ("pii", "reject", "SELECT Email FROM Customer"),
    ("pii", "reject", "SELECT c.Phone FROM Customer AS c"),
    ("pii", "reject", "SELECT lower(Email) FROM Customer"),
    ("pii", "reject", "SELECT FirstName FROM Customer WHERE Email LIKE '%@gmail.com'"),
    ("pii", "reject", "SELECT FirstName FROM Customer ORDER BY Address"),
    ("pii", "reject", "WITH x AS (SELECT Email AS e FROM Customer) SELECT e FROM x"),
    ("pii", "reject", "SELECT (SELECT Email FROM Customer LIMIT 1) AS e FROM Album"),
    ("pii", "reject", "SELECT Phone FROM Customer JOIN Invoice USING (CustomerId)"),
    ("pii", "reject", "SELECT BillingAddress FROM Invoice"),
    ("pii", "reject", "SELECT * FROM Customer"),
    ("pii", "reject", "SELECT c.* FROM Customer c"),
    ("pii", "reject", "SELECT Name FROM Artist UNION SELECT * FROM Genre"),
    # --- evasion attempts added after the guard was written (probing, not designing to pass) ---
    ("evasion", "reject", 'SELECT "Email" FROM Customer'),
    ("evasion", "reject", "SELECT `Email` FROM Customer"),
    ("evasion", "reject", "SELECT [Email] FROM Customer"),
    ("evasion", "reject", "select customer.email from customer"),
    ("evasion", "reject", "SELECT json_object('e', Email) FROM Customer"),
    ("evasion", "reject", "SELECT value FROM json_each((SELECT group_concat(Email) FROM Customer))"),
    ("evasion", "reject", "SELECT (SELECT c.Email) FROM Customer c"),
    ("evasion", "reject", "SELECT FirstName FROM Customer WHERE EXISTS (SELECT 1 FROM Invoice WHERE Email LIKE 'a%')"),
    ("evasion", "reject", "SELECT count(*) FROM Customer WHERE Email LIKE 'a%'"),
    ("evasion", "reject", "SELECT group_concat(FirstName || Email) FROM Customer"),
    ("evasion", "reject", "SELECT FirstName FROM temp.Customer"),
    ("evasion", "reject", "SELECT name FROM sqlite_temp_master"),
    ("evasion", "reject", "SELECT FirstName FROM Customer GROUP BY FirstName HAVING max(length(Phone)) > 3"),
    # --- malformed / evasive ---
    ("malformed", "reject", "SEL/**/ECT Name FROM Artist"),
    ("malformed", "reject", ""),
    ("malformed", "reject", "SELECT Name FROM Artist LIMIT (SELECT 100000)"),
    # --- resource exhaustion ---
    ("resource", "timeout", "SELECT count(*) FROM Track a, Track b, Track c"),
    ("resource", "capped", "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT n FROM r"),
    ("resource", "capped", "SELECT Name FROM Track LIMIT 100000"),
    ("resource", "reject", "SELECT Name FROM Track LIMIT -1"),  # negative LIMIT = unlimited in SQLite
    ("resource", "capped", "SELECT Name FROM Track"),
    # --- legitimate analytics that must keep working ---
    ("benign", "allow", "SELECT g.Name, count(*) AS tracks FROM Track t JOIN Genre g ON g.GenreId = t.GenreId GROUP BY g.Name ORDER BY tracks DESC LIMIT 10"),
    ("benign", "allow", "SELECT c.Country, round(sum(i.Total), 2) AS revenue FROM Invoice i JOIN Customer c ON c.CustomerId = i.CustomerId GROUP BY c.Country ORDER BY revenue DESC LIMIT 5"),
    ("benign", "allow", "SELECT strftime('%Y', InvoiceDate) AS yr, count(*) FROM Invoice GROUP BY yr"),
    ("benign", "allow", "WITH top AS (SELECT ArtistId, count(*) n FROM Album GROUP BY ArtistId) SELECT a.Name, top.n FROM top JOIN Artist a USING (ArtistId) ORDER BY top.n DESC LIMIT 5"),
    ("benign", "allow", "SELECT Name, Milliseconds, rank() OVER (PARTITION BY GenreId ORDER BY Milliseconds DESC) AS r FROM Track LIMIT 20"),
    ("benign", "allow", "SELECT FirstName, LastName, Country FROM Customer WHERE Country = 'Brazil' LIMIT 50"),
    ("benign", "allow", "SELECT Title FROM Album WHERE ArtistId = (SELECT ArtistId FROM Artist WHERE Name = 'AC/DC')"),
    ("benign", "allow", "SELECT Name FROM Artist UNION SELECT Name FROM Genre LIMIT 30"),
    ("benign", "allow", "SELECT CASE WHEN UnitPrice > 1 THEN 'video' ELSE 'audio' END AS kind, count(*) FROM Track GROUP BY kind"),
    ("benign", "allow", "SELECT p.Name, count(pt.TrackId) FROM Playlist p LEFT JOIN PlaylistTrack pt USING (PlaylistId) GROUP BY p.PlaylistId LIMIT 20"),
    ("benign", "allow", "SELECT BillingCountry, avg(Total) FROM Invoice GROUP BY BillingCountry HAVING count(*) > 10"),
    ("benign", "allow", "SELECT count(DISTINCT CustomerId) FROM Invoice"),
]


def outcome(db, sql: str) -> str:
    from .db import TimedOut
    from .guard import Rejected

    try:
        r = db.query(sql)
    except Rejected:
        return "reject"
    except TimedOut:
        return "timeout"
    return "capped" if r["truncated"] else "allow"


def main():
    from .db import Database
    from .policy import Policy

    db = Database(Path(sys.argv[1] if len(sys.argv) > 1 else "data/chinook.sqlite"), Policy.load(Path("policy.chinook.json")))
    by_cat = defaultdict(lambda: [0, 0])
    failures = []
    for cat, expected, sql in CASES:
        got = outcome(db, sql)
        by_cat[cat][0] += got == expected
        by_cat[cat][1] += 1
        if got != expected:
            failures.append((cat, expected, got, sql))
    print("| Category | Cases | As expected |\n|---|---|---|")
    for cat, (ok, n) in by_cat.items():
        print(f"| {cat} | {n} | {ok}/{n} |")
    for f in failures:
        print("MISMATCH", f)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
