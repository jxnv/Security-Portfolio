from __future__ import annotations

from pathlib import Path

from cbcli.data.sqlite import get_connection


class JournalRepository:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def log_order_attempt(
        self,
        *,
        mode: str,
        profile: str,
        dry_run: bool,
        action: str,
        product_id: str | None,
        side: str | None,
        order_type: str | None,
        base_size: str | None,
        quote_size: str | None,
        limit_price: str | None,
        status: str,
        success: bool,
        order_id: str | None,
        client_order_id: str | None,
        error_message: str | None,
        notes: str | None = None,
    ) -> None:
        conn = get_connection(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO trade_journal (
                    mode, profile, dry_run, action, product_id, side, order_type,
                    base_size, quote_size, limit_price, status, success,
                    order_id, client_order_id, error_message, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mode,
                    profile,
                    1 if dry_run else 0,
                    action,
                    product_id,
                    side,
                    order_type,
                    base_size,
                    quote_size,
                    limit_price,
                    status,
                    1 if success else 0,
                    order_id,
                    client_order_id,
                    error_message,
                    notes,
                ),
            )
            conn.commit()
        finally:
            conn.close()