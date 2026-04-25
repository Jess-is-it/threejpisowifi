import os
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row


DATABASE_URL = os.environ["DATABASE_URL"]


@contextmanager
def get_conn():
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def fetch_one(query: str, params: tuple = ()):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()


def fetch_all(query: str, params: tuple = ()):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()
