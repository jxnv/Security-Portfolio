from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

from cbcli.core.enums import OrderSide, OrderType
from cbcli.core.exceptions import ValidationError
from cbcli.core.models import OrderRequest
from cbcli.risk.guards import guard_positive_decimal


class OrderService:
    def build_market_buy_by_quote(self, product_id: str, quote_size: Decimal) -> OrderRequest:
        guard_positive_decimal(quote_size, "quote_size")
        return OrderRequest(
            client_order_id=str(uuid4()),
            product_id=product_id,
            side=OrderSide.BUY,
            order_type=OrderType.MARKET,
            quote_size=quote_size,
        )

    def build_market_sell_by_base(self, product_id: str, base_size: Decimal) -> OrderRequest:
        guard_positive_decimal(base_size, "base_size")
        return OrderRequest(
            client_order_id=str(uuid4()),
            product_id=product_id,
            side=OrderSide.SELL,
            order_type=OrderType.MARKET,
            base_size=base_size,
        )

    def build_limit_buy(self, product_id: str, base_size: Decimal, limit_price: Decimal) -> OrderRequest:
        guard_positive_decimal(base_size, "base_size")
        guard_positive_decimal(limit_price, "limit_price")
        return OrderRequest(
            client_order_id=str(uuid4()),
            product_id=product_id,
            side=OrderSide.BUY,
            order_type=OrderType.LIMIT,
            base_size=base_size,
            limit_price=limit_price,
        )

    def build_limit_sell(self, product_id: str, base_size: Decimal, limit_price: Decimal) -> OrderRequest:
        guard_positive_decimal(base_size, "base_size")
        guard_positive_decimal(limit_price, "limit_price")
        return OrderRequest(
            client_order_id=str(uuid4()),
            product_id=product_id,
            side=OrderSide.SELL,
            order_type=OrderType.LIMIT,
            base_size=base_size,
            limit_price=limit_price,
        )

    def list_open_orders(self, exchange):
        return exchange.list_open_orders()

    def cancel_order(self, exchange, order_id: str) -> bool:
        return exchange.cancel_order(order_id)