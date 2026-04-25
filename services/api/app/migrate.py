from pathlib import Path

from .db import get_conn


def main():
    migration_dir = Path("/database/migrations")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())")
            cur.execute("SELECT filename FROM schema_migrations")
            applied = {row["filename"] for row in cur.fetchall()}
            for path in sorted(migration_dir.glob("*.sql")):
                if path.name in applied:
                    continue
                cur.execute(path.read_text())
                cur.execute("INSERT INTO schema_migrations(filename) VALUES (%s)", (path.name,))
                print(f"applied {path.name}")


if __name__ == "__main__":
    main()
