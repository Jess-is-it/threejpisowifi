#!/usr/bin/env python3
import os
import sys
from datetime import datetime, timezone

import psycopg
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def load_runtime_env():
    if os.environ.get("DATABASE_URL"):
        return
    try:
        with open("/opt/radius/runtime.env", encoding="utf-8") as env_file:
            for line in env_file:
                key, _, value = line.strip().partition("=")
                if key and key not in os.environ:
                    os.environ[key] = value
    except FileNotFoundError:
        pass


def clean(value):
    return None if value in ("", "(null)", "None") else value


def log(cur, username, nas_ip, nas_identifier, calling_station_id, result, message):
    cur.execute(
        """
        INSERT INTO radius_auth_logs(username, nas_ip, nas_identifier, calling_station_id, result, reply_message, diagnostic_reason)
        VALUES (%s, NULLIF(%s, '')::inet, %s, %s, %s, %s, %s)
        """,
        (username, nas_ip or "", nas_identifier, calling_station_id, result, message, message),
    )


def reject(message):
    print(f'Reply-Message := "{message}"')
    return 1


def main():
    load_runtime_env()
    username, password, nas_ip, nas_identifier, calling_station_id = [clean(v) for v in sys.argv[1:6]]
    grace = int(os.getenv("ACTIVE_SESSION_GRACE_SECONDS", "180"))
    try:
        conn = psycopg.connect(os.environ["DATABASE_URL"])
    except Exception:
        return reject("Database lookup failed")
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.password_hash, u.status, w.time_remaining_seconds, w.valid_until, w.is_unlimited
                FROM users u
                LEFT JOIN wallets w ON w.user_id = u.id
                WHERE u.username = %s
                """,
                (username,),
            )
            user = cur.fetchone()
            result = "reject"
            message = "Unknown user"
            if not user:
                log(cur, username, nas_ip, nas_identifier, calling_station_id, result, message)
                return reject(message)
            user_id, password_hash, status, remaining, valid_until, unlimited = user
            if status != "active":
                message = "User disabled"
            elif not password or not pwd_context.verify(password, password_hash):
                message = "Invalid password"
            elif not unlimited and (remaining or 0) <= 0 and valid_until and valid_until <= datetime.now(timezone.utc):
                message = "Account expired"
            elif not unlimited and (remaining or 0) <= 0 and not (valid_until and valid_until > datetime.now(timezone.utc)):
                message = "No active wallet balance"
            else:
                cur.execute(
                    """
                    SELECT 1 FROM sessions
                    WHERE user_id = %s
                      AND stop_time IS NULL
                      AND last_update_time > now() - (%s || ' seconds')::interval
                    LIMIT 1
                    """,
                    (user_id, grace),
                )
                if cur.fetchone():
                    message = "Active session already exists"
                else:
                    result = "accept"
                    message = "Access accepted"
            log(cur, username, nas_ip, nas_identifier, calling_station_id, result, message)
            if result == "accept":
                print(f'Reply-Message := "{message}"')
                if not unlimited and remaining and remaining > 0:
                    print(f"Session-Timeout := {remaining}")
                return 0
            return reject(message)


if __name__ == "__main__":
    sys.exit(main())
