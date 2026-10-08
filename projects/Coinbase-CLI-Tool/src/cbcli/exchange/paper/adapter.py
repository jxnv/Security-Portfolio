from __future__ import annotations

from decimal import Decimal
from uuid import uuid4
import json
from pathlib import Path

from cbcli.core.enums import OrderSide, OrderType
from cbcli.core.exceptions import ValidationError
from cbcli.core.models import Account, OrderRequest, OrderResult, Product, Ticker
from cbcli.exchange.base import ExchangeAdapter


class PaperAdapter(ExchangeAdapter):
    def __init__(self, starting_cash: float = 10000.0):
        self.state_file = Path("./paper_state.json")

        if self.state_file.exists():
            self._load_state()
        else:
            self.cash = Decimal(str(starting_cash))
            self.positions: dict[str, Decimal] = {}
            self.open_orders: dict[str, OrderResult] = {}
            self._save_state()

        self.mock_prices = {
            "BTC-USD": Decimal("85000"),
            "ETH-USD": Decimal("2000"),
            "SOL-USD": Decimal("140"),
        }

    def list_accounts(self) -> list[Account]:
        accounts = [
            Account(
                uuid="paper-usd",
                currency="USD",
                available_balance=self.cash,
                hold_balance=Decimal("0"),
                total_balance=self.cash,
            )
        ]

        for asset, qty in self.positions.items():
            if qty > 0:
                accounts.append(
                    Account(
                        uuid=f"paper-{asset.lower()}",
                        currency=asset,
                        available_balance=qty,
                        hold_balance=Decimal("0"),
                        total_balance=qty,
                    )
                )

        return accounts

    def _save_state(self):
        data = {
            "cash": str(self.cash),
            "positions": {k: str(v) for k, v in self.positions.items()},
        }
        self.state_file.write_text(json.dumps(data))


    def _load_state(self):
        data = json.loads(self.state_file.read_text())
        self.cash = Decimal(data["cash"])
        self.positions = {k: Decimal(v) for k, v in data["positions"].items()}
        self.open_orders = {}

    def list_products(self) -> list[Product]:
        return [
            Product(
                product_id=product_id,
                base_currency=product_id.split("-")[0],
                quote_currency=product_id.split("-")[1],
                price=price,
                status="online",
            )
            for product_id, price in self.mock_prices.items()
        ]

    def get_product(self, product_id: str) -> Product:
        if product_id not in self.mock_prices:
            raise ValidationError(f"Unknown paper product: {product_id}")

        return Product(
            product_id=product_id,
            base_currency=product_id.split("-")[0],
            quote_currency=product_id.split("-")[1],
            price=self.mock_prices[product_id],
            status="online",
        )

    def get_ticker(self, product_id: str) -> Ticker:
        product = self.get_product(product_id)
        return Ticker(product_id=product_id, price=product.price)

    def place_order(self, order: OrderRequest) -> OrderResult:
        if order.order_type == OrderType.MARKET:
            return self._place_market(order)
        if order.order_type == OrderType.LIMIT:
            return self._place_limit(order)
        raise ValidationError(f"Unsupported paper order type: {order.order_type}")

    def list_open_orders(self) -> list[OrderResult]:
        return list(self.open_orders.values())

    def cancel_order(self, order_id: str) -> bool:
        return self.open_orders.pop(order_id, None) is not None

    def _place_market(self, order: OrderRequest) -> OrderResult:
        price = self.get_ticker(order.product_id).price
        base_asset = order.product_id.split("-")[0]

        if order.side == OrderSide.BUY:
            if order.quote_size is None:
                raise ValidationError("Market BUY requires quote_size.")
            cost = order.quote_size
            qty = cost / price
            if cost > self.cash:
                return OrderResult(success=False, error_message="Insufficient paper USD balance")
            self.cash -= cost
            self.positions[base_asset] = self.positions.get(base_asset, Decimal("0")) + qty
        else:
            if order.base_size is None:
                raise ValidationError("Market SELL requires base_size.")
            owned = self.positions.get(base_asset, Decimal("0"))
            if order.base_size > owned:
                return OrderResult(success=False, error_message="Insufficient paper asset balance")
            self.positions[base_asset] = owned - order.base_size
            self.cash += order.base_size * price
        self._save_state()

        return OrderResult(
            success=True,
            order_id=str(uuid4()),
            client_order_id=order.client_order_id,
            product_id=order.product_id,
            side=order.side,
            order_type=order.order_type,
            status="FILLED",
            raw={"paper": True},
        )

    def _place_limit(self, order: OrderRequest) -> OrderResult:
        if order.base_size is None or order.limit_price is None:
            raise ValidationError("Limit order requires base_size and limit_price.")

        order_id = str(uuid4())
        result = OrderResult(
            success=True,
            order_id=order_id,
            client_order_id=order.client_order_id,
            product_id=order.product_id,
            side=order.side,
            order_type=order.order_type,
            status="OPEN",
            raw={"paper": True},
        )
        self.open_orders[order_id] = result
        self._save_state()
        return result