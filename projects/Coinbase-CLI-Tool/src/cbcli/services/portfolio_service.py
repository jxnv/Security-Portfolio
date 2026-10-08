from __future__ import annotations

from decimal import Decimal

from cbcli.core.models import Position
from cbcli.exchange.base import ExchangeAdapter


class PortfolioService:
    def __init__(self, exchange: ExchangeAdapter):
        self.exchange = exchange

    def get_balances(self):
        return self.exchange.list_accounts()

    def get_positions(self) -> list[Position]:
        positions: list[Position] = []

        accounts = self.exchange.list_accounts()
        for account in accounts:
            if account.total_balance <= 0:
                continue

            if account.currency == "USD":
                positions.append(
                    Position(
                        asset="USD",
                        quantity=account.total_balance,
                        usd_value=account.total_balance,
                    )
                )
            else:
                product_id = f"{account.currency}-USD"
                usd_value = None
                try:
                    ticker = self.exchange.get_ticker(product_id)
                    usd_value = account.total_balance * ticker.price
                except Exception:
                    usd_value = None

                positions.append(
                    Position(
                        asset=account.currency,
                        quantity=account.total_balance,
                        usd_value=usd_value,
                    )
                )

        return positions

    def get_total_usd_value(self) -> Decimal:
        total = Decimal("0")
        for position in self.get_positions():
            if position.usd_value is not None:
                total += position.usd_value
        return total