from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Optional

from cbcli.core.enums import OrderSide, OrderType


@dataclass(slots=True)
class Account:
    uuid: str
    currency: str
    available_balance: Decimal
    hold_balance: Decimal = Decimal("0")
    total_balance: Decimal = Decimal("0")


@dataclass(slots=True)
class Product:
    product_id: str
    base_currency: str
    quote_currency: str
    price: Optional[Decimal] = None
    price_increment: Optional[Decimal] = None
    base_increment: Optional[Decimal] = None
    quote_increment: Optional[Decimal] = None
    status: Optional[str] = None


@dataclass(slots=True)
class Ticker:
    product_id: str
    price: Decimal


@dataclass(slots=True)
class Position:
    asset: str
    quantity: Decimal
    usd_value: Optional[Decimal] = None


@dataclass(slots=True)
class OrderRequest:
    client_order_id: str
    product_id: str
    side: OrderSide
    order_type: OrderType
    base_size: Optional[Decimal] = None
    quote_size: Optional[Decimal] = None
    limit_price: Optional[Decimal] = None
    post_only: bool = False
    metadata: dict = field(default_factory=dict)


@dataclass(slots=True)
class OrderResult:
    success: bool
    order_id: Optional[str] = None
    client_order_id: Optional[str] = None
    product_id: Optional[str] = None
    side: Optional[OrderSide] = None
    order_type: Optional[OrderType] = None
    status: Optional[str] = None
    raw: dict = field(default_factory=dict)
    error_message: Optional[str] = None