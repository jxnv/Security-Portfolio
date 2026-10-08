from __future__ import annotations

from decimal import Decimal
from cbcli.data.sqlite import get_connection


def get_filled_trades(db_path):
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT *
            FROM trade_journal
            WHERE success = 1 AND status IN ('FILLED', 'DRY_RUN')
            ORDER BY ts ASC
            """
        ).fetchall()

        return rows
    finally:
        conn.close()