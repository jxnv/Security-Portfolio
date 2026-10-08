from cbcli.core.models import Account
from cbcli.exchange.base import ExchangeAdapter


class AccountService:
    def __init__(self, exchange: ExchangeAdapter):
        self.exchange = exchange

    def list_accounts(self) -> list[Account]:
        return self.exchange.list_accounts()

    def get_nonzero_accounts(self) -> list[Account]:
        return [a for a in self.exchange.list_accounts() if a.total_balance > 0]