#!/usr/bin/env python3
import os
import sys

import psycopg


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


def int_or_zero(value):
    try:
        return int(value or 0)
    except ValueError:
        return 0


def main():
    load_runtime_env()
    username, status_type, nas_ip, nas_identifier, calling_station_id, framed_ip, session_id, in_octets, out_octets = [
        clean(v) for v in sys.argv[1:10]
    ]
    in_octets = int_or_zero(in_octets)
    out_octets = int_or_zero(out_octets)
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            user_id = row[0] if row else None
            if status_type == "Start":
                cur.execute(
                    """
                    INSERT INTO sessions(user_id, username, nas_ip, nas_identifier, calling_station_id, framed_ip_address,
                                         acct_session_id, start_time, last_update_time, input_octets, output_octets, status)
                    VALUES (%s, %s, NULLIF(%s, '')::inet, %s, %s, NULLIF(%s, '')::inet, %s, now(), now(), %s, %s, 'active')
                    ON CONFLICT (username, acct_session_id)
                    DO UPDATE SET last_update_time = now(), status = 'active', stop_time = NULL
                    """,
                    (user_id, username, nas_ip or "", nas_identifier, calling_station_id, framed_ip or "", session_id, in_octets, out_octets),
                )
            elif status_type == "Interim-Update":
                cur.execute(
                    """
                    WITH previous AS (
                        SELECT user_id, GREATEST(EXTRACT(EPOCH FROM (now() - last_update_time))::int, 0) AS elapsed
                        FROM sessions
                        WHERE username = %s AND acct_session_id = %s
                    ),
                    updated AS (
                        UPDATE sessions
                        SET last_update_time = now(),
                            input_octets = %s,
                            output_octets = %s
                        WHERE username = %s AND acct_session_id = %s
                    )
                    SELECT user_id, elapsed FROM previous
                    """,
                    (username, session_id, in_octets, out_octets, username, session_id),
                )
                session = cur.fetchone()
                if session and session[0] and session[1] > 0:
                    cur.execute(
                        """
                        UPDATE wallets
                        SET time_remaining_seconds = GREATEST(time_remaining_seconds - %s, 0),
                            updated_at = now()
                        WHERE user_id = %s AND is_unlimited = false
                        """,
                        (session[1], session[0]),
                    )
            elif status_type == "Stop":
                cur.execute(
                    """
                    UPDATE sessions
                    SET last_update_time = now(), stop_time = now(), input_octets = %s, output_octets = %s, status = 'stopped'
                    WHERE username = %s AND acct_session_id = %s
                    """,
                    (in_octets, out_octets, username, session_id),
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
