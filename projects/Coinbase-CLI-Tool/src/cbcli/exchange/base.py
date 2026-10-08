from __future__ import annotations

from abc import ABC, abstractmethod

from cbcli.core.models import Account, OrderRequest, OrderResult, Product, Ticker


class ExchangeAdapter(ABC):
    @abstractmethod
    def list_accounts(self) -> list[Account]:
        raise NotImplementedError

    @abstractmethod
    def list_products(self) -> list[Product]:
        raise NotImplementedError

    @abstractmethod
    def get_product(self, product_id: str) -> Product:
        raise NotImplementedError

    @abstractmethod
    def get_ticker(self, product_id: str) -> Ticker:
        raise NotImplementedError

    @abstractmethod
    def place_order(self, order: OrderRequest) -> OrderResult:
        raise NotImplementedError

    @abstractmethod
    def list_open_orders(self) -> list[OrderResult]:
        raise NotImplementedError

    @abstractmethod
    def cancel_order(self, order_id: str) -> bool:
        raise NotImplementedError