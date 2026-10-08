from cbcli.core.config import get_settings
from cbcli.data.journal import JournalRepository
from cbcli.data.sqlite import init_db
from cbcli.exchange.coinbase.adapter import CoinbaseAdapter
from cbcli.exchange.paper.adapter import PaperAdapter
from cbcli.services.account_service import AccountService
from cbcli.services.order_service import OrderService
from cbcli.services.portfolio_service import PortfolioService
from cbcli.services.execution_service import ExecutionService
from cbcli.services.portfolio_intelligence_service import PortfolioIntelligenceService


def build_exchange(settings):
    if settings.mode.value == "live":
        return CoinbaseAdapter(settings)
    return PaperAdapter(starting_cash=settings.paper_starting_cash)


def build_services():
    settings = get_settings()
    init_db(settings.db_path)

    exchange = build_exchange(settings)
    journal_repo = JournalRepository(settings.db_path)

    return {
        "settings": settings,
        "exchange": exchange,
        "journal_repo": journal_repo,
        "account_service": AccountService(exchange),
        "order_service": OrderService(),
        "portfolio_service": PortfolioService(exchange),
        "execution_service": ExecutionService(settings, exchange, journal_repo),
        "portfolio_intelligence_service": PortfolioIntelligenceService(exchange),
    }