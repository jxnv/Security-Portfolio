from __future__ import annotations

from decimal import Decimal

from cbcli.core.exceptions import ValidationError
from cbcli.core.models import OrderRequest, OrderResult
from cbcli.data.journal import JournalRepository
from cbcli.risk.guards import guard_max_order_usd
from cbcli.risk.slippage import guard_slippage


class ExecutionService:
    def __init__(self, settings, exchange, journal_repo: JournalRepository):
        self.settings = settings
        self.exchange = exchange
        self.journal_repo = journal_repo

    def execute_order(self, order: OrderRequest, reference_price: Decimal | None = None) -> OrderResult:
        try:
            notional_usd = self._estimate_notional_usd(order)
            guard_max_order_usd(notional_usd, Decimal(str(self.settings.max_order_usd)))

            current_price = self.exchange.get_ticker(order.product_id).price

            if reference_price is not None:
                guard_slippage(
                    reference_price=reference_price,
                    observed_price=current_price,
                    max_slippage_pct=Decimal(str(self.settings.max_slippage_pct)),
                )

            if self.settings.dry_run:
                result = OrderResult(
                    success=True,
                    order_id=None,
                    client_order_id=order.client_order_id,
                    product_id=order.product_id,
                    side=order.side,
                    order_type=order.order_type,
                    status="DRY_RUN",
                    raw={"dry_run": True},
                    error_message=None,
                )
                self._log(order, result, notes=f"estimated_notional_usd={notional_usd}")
                return result

            result = self.exchange.place_order(order)
            self._log(order, result, notes=f"estimated_notional_usd={notional_usd}")
            return result

        except Exception as exc:
            failure = OrderResult(
                success=False,
                order_id=None,
                client_order_id=order.client_order_id,
                product_id=order.product_id,
                side=order.side,
                order_type=order.order_type,
                status="REJECTED",
                raw={},
                error_message=str(exc),
            )
            self._log(order, failure, notes="execution guard failure")
            raise

    def _estimate_notional_usd(self, order: OrderRequest) -> Decimal:
        if order.quote_size is not None:
            return order.quote_size

        ticker = self.exchange.get_ticker(order.product_id)
        if order.base_size is None:
            raise ValidationError("Unable to estimate order notional without base_size or quote_size")
        return order.base_size * ticker.price

    def _log(self, order: OrderRequest, result: OrderResult, notes: str | None = None) -> None:
        self.journal_repo.log_order_attempt(
            mode=self.settings.mode.value,
            profile=self.settings.profile,
            dry_run=self.settings.dry_run,
            action="execute_order",
            product_id=order.product_id,
            side=order.side.value if order.side else None,
            order_type=order.order_type.value if order.order_type else None,
            base_size=str(order.base_size) if order.base_size is not None else None,
            quote_size=str(order.quote_size) if order.quote_size is not None else None,
            limit_price=str(order.limit_price) if order.limit_price is not None else None,
            status=result.status or "UNKNOWN",
            success=result.success,
            order_id=result.order_id,
            client_order_id=result.client_order_id,
            error_message=result.error_message,
            notes=notes,
        )