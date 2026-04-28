#!/usr/bin/env python3
import os
import sys
from datetime import datetime, timezone

import psycopg
from psycopg.types.json import Json


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
    except (TypeError, ValueError):
        return 0


def log_accounting(cur, payload, result, diagnostic):
    cur.execute(
        """
        INSERT INTO radius_accounting_logs(
            username, acct_status_type, acct_session_id, nas_ip, nas_identifier,
            calling_station_id, framed_ip_address, acct_session_time, input_octets,
            output_octets, raw_payload, result, diagnostic_reason
        )
        VALUES (%s, %s, %s, NULLIF(%s, '')::inet, %s, %s, NULLIF(%s, '')::inet, %s, %s, %s, %s, %s, %s)
        """,
        (
            payload["username"],
            payload["status_type"],
            payload["session_id"],
            payload["nas_ip"] or "",
            payload["nas_identifier"],
            payload["calling_station_id"],
            payload["framed_ip"] or "",
            payload["session_time"],
            payload["in_octets"],
            payload["out_octets"],
            Json(payload),
            result,
            diagnostic,
        ),
    )


def deduct_wallet(cur, user_id, username, session_id, elapsed_seconds):
    if not user_id or elapsed_seconds <= 0:
        return 0, None, None
    cur.execute(
        """
        SELECT time_remaining_seconds, is_unlimited
        FROM wallets
        WHERE user_id = %s
        FOR UPDATE
        """,
        (user_id,),
    )
    wallet = cur.fetchone()
    if not wallet:
        return 0, None, None
    before, unlimited = int(wallet[0] or 0), bool(wallet[1])
    if unlimited or before <= 0:
        return 0, before, before
    deducted = min(before, elapsed_seconds)
    after = max(before - deducted, 0)
    cur.execute(
        """
        UPDATE wallets
        SET time_remaining_seconds = %s,
            updated_at = now()
        WHERE user_id = %s
        """,
        (after, user_id),
    )
    cur.execute(
        """
        INSERT INTO transactions(user_id, source, type, amount_seconds, reference, note)
        VALUES (%s, 'ACCOUNTING', 'DEBIT', %s, %s, %s)
        """,
        (user_id, deducted, session_id, f"Accounting time deduction for {username}: {deducted} seconds"),
    )
    return deducted, before, after


def find_session(cur, payload):
    cur.execute(
        """
        SELECT id, user_id, last_update_time, acct_session_time
        FROM sessions
        WHERE username = %s
          AND acct_session_id = %s
          AND stop_time IS NULL
        ORDER BY last_update_time DESC
        LIMIT 1
        """,
        (payload["username"], payload["session_id"]),
    )
    return cur.fetchone()


def elapsed_for_update(last_update_time, previous_session_time, packet_session_time):
    now = datetime.now(timezone.utc)
    clock_elapsed = max(int((now - last_update_time).total_seconds()), 0) if last_update_time else 0
    session_delta = max(int(packet_session_time or 0) - int(previous_session_time or 0), 0)
    return max(clock_elapsed, session_delta)


def handle_start(cur, payload, user_id):
    if not user_id:
        log_accounting(cur, payload, "ignored", "User not found")
        return "Accounting Start ignored: User not found"
    cur.execute(
        """
        INSERT INTO sessions(
            user_id, username, nas_ip, nas_identifier, calling_station_id, framed_ip_address,
            acct_session_id, acct_unique_session_id, start_time, last_update_time,
            acct_session_time, input_octets, output_octets, status, updated_at
        )
        VALUES (%s, %s, NULLIF(%s, '')::inet, %s, %s, NULLIF(%s, '')::inet, %s, %s, now(), now(), %s, %s, %s, 'ACTIVE', now())
        ON CONFLICT (username, acct_session_id)
        DO UPDATE SET user_id = EXCLUDED.user_id,
                      nas_ip = EXCLUDED.nas_ip,
                      nas_identifier = EXCLUDED.nas_identifier,
                      calling_station_id = EXCLUDED.calling_station_id,
                      framed_ip_address = EXCLUDED.framed_ip_address,
                      acct_unique_session_id = EXCLUDED.acct_unique_session_id,
                      last_update_time = now(),
                      acct_session_time = EXCLUDED.acct_session_time,
                      input_octets = EXCLUDED.input_octets,
                      output_octets = EXCLUDED.output_octets,
                      status = 'ACTIVE',
                      stop_time = NULL,
                      updated_at = now()
        """,
        (
            user_id,
            payload["username"],
            payload["nas_ip"] or "",
            payload["nas_identifier"],
            payload["calling_station_id"],
            payload["framed_ip"] or "",
            payload["session_id"],
            payload["unique_session_id"],
            payload["session_time"],
            payload["in_octets"],
            payload["out_octets"],
        ),
    )
    log_accounting(cur, payload, "accepted", "Session Created")
    return "Session Created"


def handle_interim(cur, payload):
    session = find_session(cur, payload)
    if not session:
        log_accounting(cur, payload, "ignored", "No matching active session found")
        return "No matching active session found"
    session_id, user_id, last_update_time, previous_session_time = session
    elapsed = elapsed_for_update(last_update_time, previous_session_time, payload["session_time"])
    deducted, before, after = deduct_wallet(cur, user_id, payload["username"], payload["session_id"], elapsed)
    cur.execute(
        """
        UPDATE sessions
        SET last_update_time = now(),
            acct_session_time = %s,
            input_octets = %s,
            output_octets = %s,
            status = 'ACTIVE',
            updated_at = now()
        WHERE id = %s
        """,
        (payload["session_time"], payload["in_octets"], payload["out_octets"], session_id),
    )
    diagnostic = f"Session Updated; Wallet Deducted: {deducted} seconds"
    if before is not None:
        diagnostic += f"; Wallet Before: {before}; Wallet After: {after}"
    log_accounting(cur, payload, "accepted", diagnostic)
    return diagnostic


def handle_stop(cur, payload):
    session = find_session(cur, payload)
    if not session:
        log_accounting(cur, payload, "ignored", "No matching active session found")
        return "No matching active session found"
    session_id, user_id, last_update_time, previous_session_time = session
    elapsed = elapsed_for_update(last_update_time, previous_session_time, payload["session_time"])
    deducted, before, after = deduct_wallet(cur, user_id, payload["username"], payload["session_id"], elapsed)
    cur.execute(
        """
        UPDATE sessions
        SET last_update_time = now(),
            stop_time = now(),
            acct_session_time = %s,
            input_octets = %s,
            output_octets = %s,
            status = 'STOPPED',
            updated_at = now()
        WHERE id = %s
        """,
        (payload["session_time"], payload["in_octets"], payload["out_octets"], session_id),
    )
    diagnostic = f"Session Stopped; Wallet Deducted: {deducted} seconds"
    if before is not None:
        diagnostic += f"; Wallet Before: {before}; Wallet After: {after}"
    log_accounting(cur, payload, "accepted", diagnostic)
    return diagnostic


def main():
    load_runtime_env()
    username, status_type, nas_ip, nas_identifier, calling_station_id, framed_ip, session_id, in_octets, out_octets, session_time, unique_session_id = [
        clean(v) for v in sys.argv[1:12]
    ]
    payload = {
        "username": username,
        "status_type": status_type,
        "nas_ip": nas_ip,
        "nas_identifier": nas_identifier,
        "calling_station_id": calling_station_id,
        "framed_ip": framed_ip,
        "session_id": session_id,
        "unique_session_id": unique_session_id,
        "in_octets": int_or_zero(in_octets),
        "out_octets": int_or_zero(out_octets),
        "session_time": int_or_zero(session_time),
    }
    try:
        conn = psycopg.connect(os.environ["DATABASE_URL"])
    except Exception:
        print('Reply-Message := "Database error"')
        return 0
    with conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s AND status = 'active'", (username,))
            row = cur.fetchone()
            user_id = row[0] if row else None
            if status_type == "Start":
                diagnostic = handle_start(cur, payload, user_id)
            elif status_type == "Interim-Update":
                diagnostic = handle_interim(cur, payload)
            elif status_type == "Stop":
                diagnostic = handle_stop(cur, payload)
            else:
                log_accounting(cur, payload, "ignored", "Accounting packet received but ignored")
                diagnostic = "Accounting packet received but ignored"
    print(f'Reply-Message := "{diagnostic}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
