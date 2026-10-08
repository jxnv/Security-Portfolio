# Coinbase CLI Architecture

## Goals

* Fast manual execution from terminal
* Modular design for future strategies and exchanges
* Safe-by-default order flow
* Clean separation between exchange access, market data, portfolio logic, and strategy logic
* Easy testing with paper/live modes

## Project Layout

```text
coinbase_cli/
├── pyproject.toml
├── README.md
├── .env.example
├── config/
│   ├── default.yaml
│   └── profiles/
│       ├── paper.yaml
│       └── live.yaml
├── src/
│   └── cbcli/
│       ├── __init__.py
│       ├── main.py
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── app.py
│       │   ├── commands/
│       │   │   ├── account.py
│       │   │   ├── orders.py
│       │   │   ├── portfolio.py
│       │   │   ├── market.py
│       │   │   ├── watch.py
│       │   │   ├── risk.py
│       │   │   ├── strategies.py
│       │   │   └── backtest.py
│       ├── core/
│       │   ├── config.py
│       │   ├── logging.py
│       │   ├── exceptions.py
│       │   ├── models.py
│       │   ├── enums.py
│       │   └── utils.py
│       ├── exchange/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── coinbase/
│       │   │   ├── __init__.py
│       │   │   ├── auth.py
│       │   │   ├── rest.py
│       │   │   ├── websocket.py
│       │   │   ├── mapper.py
│       │   │   └── adapter.py
│       │   └── paper/
│       │       ├── __init__.py
│       │       └── adapter.py
│       ├── services/
│       │   ├── account_service.py
│       │   ├── market_service.py
│       │   ├── order_service.py
│       │   ├── portfolio_service.py
│       │   ├── pnl_service.py
│       │   ├── rebalance_service.py
│       │   ├── risk_service.py
│       │   ├── execution_service.py
│       │   └── watch_service.py
│       ├── strategies/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── momentum.py
│       │   ├── mean_reversion.py
│       │   ├── breakout.py
│       │   └── registry.py
│       ├── risk/
│       │   ├── __init__.py
│       │   ├── sizing.py
│       │   ├── limits.py
│       │   ├── guards.py
│       │   └── stops.py
│       ├── data/
│       │   ├── __init__.py
│       │   ├── schemas.py
│       │   ├── repository.py
│       │   └── sqlite.py
│       ├── backtest/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   ├── fills.py
│       │   ├── metrics.py
│       │   └── loaders.py
│       └── ui/
│           ├── tables.py
│           ├── formatters.py
│           └── prompts.py
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/
```

## Design Rules

### 1. CLI layer stays thin

CLI command files should only:

* parse flags and arguments
* call a service
* print formatted output

No Coinbase API logic should live in CLI commands.

### 2. Exchange adapter pattern

Everything talks to an exchange interface, not directly to Coinbase.
That keeps future expansion possible for paper trading or another exchange.

### 3. Services contain business logic

Examples:

* order sizing
* fee-aware execution
* portfolio valuation
* rebalancing logic
* PnL calculations

### 4. Strategies are plugins

A strategy should expose a common interface:

* name
* required inputs
* signal generation method
* optional risk parameters

### 5. Storage is abstracted

Use SQLite first for:

* fills
* orders
* snapshots
* strategy runs
* journal notes

Later this can be swapped for Postgres without touching strategy code.

## Core Interfaces

### Exchange adapter

```python
from abc import ABC, abstractmethod
from typing import Iterable
from cbcli.core.models import Account, Product, OrderRequest, OrderResult, Position, Ticker

class ExchangeAdapter(ABC):
    @abstractmethod
    def list_accounts(self) -> list[Account]: ...

    @abstractmethod
    def list_products(self) -> list[Product]: ...

    @abstractmethod
    def get_ticker(self, product_id: str) -> Ticker: ...

    @abstractmethod
    def place_order(self, order: OrderRequest) -> OrderResult: ...

    @abstractmethod
    def cancel_order(self, order_id: str) -> bool: ...

    @abstractmethod
    def list_open_orders(self) -> list[OrderResult]: ...

    @abstractmethod
    def list_positions(self) -> list[Position]: ...
```

### Strategy interface

```python
from abc import ABC, abstractmethod
from cbcli.core.models import MarketSnapshot, Signal

class Strategy(ABC):
    name: str

    @abstractmethod
    def generate_signal(self, snapshot: MarketSnapshot) -> Signal | None: ...
```

## Recommended Build Order

### Phase 1: foundation

* config loader
* logger
* domain models
* exchange adapter base
* Coinbase adapter
* paper adapter
* account and order services

### Phase 2: CLI MVP

* `balance`
* `portfolio`
* `buy`
* `sell`
* `orders`
* `cancel`
* `watch`

### Phase 3: safety and quality

* dry-run mode
* max order size guards
* slippage guard
* live vs paper profile selection
* journaling to sqlite

### Phase 4: portfolio intelligence

* PnL tracking
* exposure report
* allocation report
* rebalance suggestions

### Phase 5: strategy engine

* strategy registry
* signal scanning
* backtest engine
* strategy configs

## Important Non-Negotiables

* Never let strategies call Coinbase directly
* Never mix UI formatting with business logic
* Never place live orders without explicit mode selection
* Every order path should pass through risk checks
* Every fill/order should be persisted locally

## MVP Commands

```bash
cb balance
cb portfolio
cb products
cb buy BTC-USD --usd 100
cb sell ETH-USD --percent 25
cb orders
cb cancel --all
cb watch BTC-USD ETH-USD
```

## Suggested Dependencies

* typer
* rich
* pydantic
* pyyaml
* sqlalchemy or sqlite3
* pandas
* httpx
* websockets
* pytest

## Next Implementation Target

Start with these files first:

* `core/models.py`
* `core/config.py`
* `exchange/base.py`
* `exchange/coinbase/adapter.py`
* `services/order_service.py`
* `cli/app.py`

After that, wire in `buy`, `sell`, `portfolio`, and `orders`.
