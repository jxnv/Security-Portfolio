from __future__ import annotations

from decimal import Decimal

from cbcli.core.exceptions import ValidationError


def calculate_slippage_pct(reference_price: Decimal, observed_price: Decimal) -> Decimal:
    if reference_price <= 0:
        raise ValidationError("reference_price must be > 0")
    return abs(observed_price - reference_price) / reference_price


def guard_slippage(
    reference_price: Decimal,
    observed_price: Decimal,
    max_slippage_pct: Decimal,
) -> None:
    slippage_pct = calculate_slippage_pct(reference_price, observed_price)
    if slippage_pct > max_slippage_pct:
        raise ValidationError(
            f"Slippage {slippage_pct:.6f} exceeds max allowed {max_slippage_pct:.6f}"
        )