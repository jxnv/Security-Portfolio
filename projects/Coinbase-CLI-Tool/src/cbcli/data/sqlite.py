from __future__ import annotations

import sqlite3
from pathlib import Path


def get_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path) -> None:
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trade_journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                mode TEXT NOT NULL,
                profile TEXT NOT NULL,
                dry_run INTEGER NOT NULL,
                action TEXT NOT NULL,
                product_id TEXT,
                side TEXT,
                order_type TEXT,
                base_size TEXT,
                quote_size TEXT,
                limit_price TEXT,
                status TEXT NOT NULL,
                success INTEGER NOT NULL,
                order_id TEXT,
                client_order_id TEXT,
                error_message TEXT,
                notes TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()