from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

from cbcli.core.enums import OrderSide, OrderType
from cbcli.core.exceptions import ExchangeError, ValidationError
from cbcli.core.logging import get_logger
from cbcli.core.models import Account, OrderRequest, OrderResult, Product, Ticker
from cbcli.exchange.base import ExchangeAdapter
from cbcli.exchange.coinbase.auth import build_coinbase_rest_client

logger = get_logger(__name__)


class CoinbaseAdapter(ExchangeAdapter):
    def __init__(self, settings):
        self.settings = settings
        self.client = build_coinbase_rest_client(settings)
        
    def _extract_balance_value(self, balance_field):
        if balance_field is None:
            return Decimal("0")

        if isinstance(balance_field, dict):
            return Decimal(str(balance_field.get("value", "0")))

        if hasattr(balance_field, "value"):
            return Decimal(str(balance_field.value))

        return Decimal("0")

    def list_accounts(self) -> list[Account]:
        try:
            response = self.client.get_accounts()
            accounts_raw = response.accounts or []

            accounts: list[Account] = []

            for item in accounts_raw:
                available = self._extract_balance_value(item.available_balance)
                hold = self._extract_balance_value(getattr(item, "hold", None))
                total = available + hold

                accounts.append(
                    Account(
                        uuid=item.uuid,
                        currency=item.currency,
                        available_balance=available,
                        hold_balance=hold,
                        total_balance=total,
                    )
                )

            return accounts

        except Exception as exc:
            raise ExchangeError(f"Failed to list Coinbase accounts: {exc}") from exc

    def list_products(self) -> list[Product]:
        try:
            response = self.client.get_products()
            products_raw = response.products
            return [self._map_product(p) for p in products_raw]
        except Exception as exc:
            raise ExchangeError(f"Failed to list Coinbase products: {exc}") from exc

    def get_product(self, product_id: str) -> Product:
        try:
            response = self.client.get_product(product_id)
            return self._map_product(response)
        except Exception as exc:
            raise ExchangeError(f"Failed to get product {product_id}: {exc}") from exc

    def get_ticker(self, product_id: str) -> Ticker:
        product = self.get_product(product_id)
        if product.price is None:
            raise ExchangeError(f"No price available for product {product_id}")
        return Ticker(product_id=product_id, price=product.price)

    def place_order(self, order: OrderRequest) -> OrderResult:
        try:
            if order.order_type == OrderType.MARKET:
                return self._place_market_order(order)
            if order.order_type == OrderType.LIMIT:
                return self._place_limit_order(order)
            raise ValidationError(f"Unsupported order type: {order.order_type}")
        except Exception as exc:
            if isinstance(exc, (ExchangeError, ValidationError)):
                raise
            raise ExchangeError(f"Failed to place Coinbase order: {exc}") from exc

    def list_open_orders(self) -> list[OrderResult]:
        try:
            response = self.client.list_orders(order_status="OPEN")
            orders_raw = response.orders
            results: list[OrderResult] = []

            for item in orders_raw:
                side_raw = item.get("side", "").upper()
                side = OrderSide.BUY if side_raw == "BUY" else OrderSide.SELL

                results.append(
                    OrderResult(
                        success=True,
                        order_id=item.get("order_id"),
                        client_order_id=item.get("client_order_id"),
                        product_id=item.get("product_id"),
                        side=side,
                        status=item.get("status"),
                        raw=item,
                    )
                )

            return results
        except Exception as exc:
            raise ExchangeError(f"Failed to list open Coinbase orders: {exc}") from exc

    def cancel_order(self, order_id: str) -> bool:
        try:
            response = self.client.cancel_orders(order_ids=[order_id])
            # Keep this conservative; result shape may vary.
            return bool(response)
        except Exception as exc:
            raise ExchangeError(f"Failed to cancel Coinbase order {order_id}: {exc}") from exc

    def _place_market_order(self, order: OrderRequest) -> OrderResult:
        if order.side == OrderSide.BUY:
            if order.quote_size is None:
                raise ValidationError("Market BUY requires quote_size.")
            response = self.client.market_order_buy(
                client_order_id=order.client_order_id or str(uuid4()),
                product_id=order.product_id,
                quote_size=str(order.quote_size),
            )
        else:
            if order.base_size is None:
                raise ValidationError("Market SELL requires base_size.")
            response = self.client.market_order_sell(
                client_order_id=order.client_order_id or str(uuid4()),
                product_id=order.product_id,
                base_size=str(order.base_size),
            )

        return self._map_order_response(order, response)

    def _place_limit_order(self, order: OrderRequest) -> OrderResult:
        if order.limit_price is None:
            raise ValidationError("Limit order requires limit_price.")
        if order.base_size is None:
            raise ValidationError("Limit order requires base_size.")

        if order.side == OrderSide.BUY:
            response = self.client.limit_order_gtc_buy(
                client_order_id=order.client_order_id or str(uuid4()),
                product_id=order.product_id,
                base_size=str(order.base_size),
                limit_price=str(order.limit_price),
                post_only=order.post_only,
            )
        else:
            response = self.client.limit_order_gtc_sell(
                client_order_id=order.client_order_id or str(uuid4()),
                product_id=order.product_id,
                base_size=str(order.base_size),
                limit_price=str(order.limit_price),
                post_only=order.post_only,
            )

        return self._map_order_response(order, response)

    def _map_product(self, item) -> Product:
        def safe_get(obj, attr, default=None):
            if isinstance(obj, dict):
                return obj.get(attr, default)
            return getattr(obj, attr, default)

        price_raw = safe_get(item, "price")

        return Product(
            product_id=safe_get(item, "product_id", ""),
            base_currency=safe_get(item, "base_currency_id", ""),
            quote_currency=safe_get(item, "quote_currency_id", ""),
            price=Decimal(str(price_raw)) if price_raw not in (None, "") else None,
            price_increment=self._to_decimal(safe_get(item, "price_increment")),
            base_increment=self._to_decimal(safe_get(item, "base_increment")),
            quote_increment=self._to_decimal(safe_get(item, "quote_increment")),
            status=safe_get(item, "status"),
        )

    def _map_order_response(self, order: OrderRequest, response: dict) -> OrderResult:
        if response.get("success"):
            success_response = response.get("success_response", {})
            return OrderResult(
                success=True,
                order_id=success_response.get("order_id"),
                client_order_id=order.client_order_id,
                product_id=order.product_id,
                side=order.side,
                order_type=order.order_type,
                status="SUBMITTED",
                raw=response,
            )

        error_response = response.get("error_response", {})
        return OrderResult(
            success=False,
            client_order_id=order.client_order_id,
            product_id=order.product_id,
            side=order.side,
            order_type=order.order_type,
            raw=response,
            error_message=error_response.get("message") or str(error_response),
        )

    @staticmethod
    def _to_decimal(value):
        if value in (None, ""):
            return None
        return Decimal(str(value))