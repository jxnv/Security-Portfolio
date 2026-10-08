from __future__ import annotations

from decimal import Decimal

from cbcli.core.exceptions import ValidationError


def guard_max_order_usd(order_notional_usd: Decimal, max_order_usd: Decimal) -> None:
    if order_notional_usd > max_order_usd:
        raise ValidationError(
            f"Order notional ${order_notional_usd} exceeds max allowed ${max_order_usd}"
        )


def guard_positive_decimal(value: Decimal, field_name: str) -> None:
    if value <= 0:
        raise ValidationError(f"{field_name} must be > 0")