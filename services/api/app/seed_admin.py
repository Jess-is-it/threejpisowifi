import sys

from .db import get_conn
from .security import hash_password


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: python -m app.seed_admin <username> <password>")
    username, password = sys.argv[1], sys.argv[2]
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM admins WHERE username = %s", (username,))
            existing = cur.fetchone()
            if existing:
                cur.execute(
                    "UPDATE admins SET password_hash = %s, status = 'active', updated_at = now() WHERE username = %s",
                    (hash_password(password), username),
                )
                print(f"updated admin {username}")
            else:
                cur.execute(
                    "INSERT INTO admins(username, password_hash, role, status) VALUES (%s, %s, 'admin', 'active')",
                    (username, hash_password(password)),
                )
                print(f"created admin {username}")


if __name__ == "__main__":
    main()
