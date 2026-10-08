# cbcli Command Reference

## Purpose

This document is a quick memory aid for the current `cbcli` command set. It explains what each command is for, when to use it, and gives example terminal commands you can copy and modify.

## General pattern

Most commands are run like this:

```bash
PYTHONPATH=src python -m cbcli.main <group> <command> [options]
```

Examples:

```bash
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
```

## Important modes

### Paper mode

Safe testing mode. No real money is used.

```bash
CBCLI_MODE=paper PYTHONPATH=src python -m cbcli.main account balance
```

### Live mode

Uses your real Coinbase account. Be careful.

```bash
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main account balance
```

### Dry-run mode

Builds and validates the trade flow without actually executing an order.

```bash
CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
```

---

# Command Groups

## 1. `account`

Use this group to inspect account balances.

### `account balance`

Shows current balances in the active mode.

Use cases:

* check starting paper cash
* confirm live account access works
* confirm balances changed after trades

Examples:

```bash
PYTHONPATH=src python -m cbcli.main account balance
CBCLI_MODE=paper PYTHONPATH=src python -m cbcli.main account balance
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main account balance
```

---

## 2. `portfolio`

Use this group to inspect positions and total portfolio value.

### `portfolio show`

Shows current holdings and estimated USD value.

Use cases:

* verify BTC or ETH was actually added after a buy
* check current exposure by asset
* sanity-check paper portfolio state persistence

Examples:

```bash
PYTHONPATH=src python -m cbcli.main portfolio show
CBCLI_MODE=paper PYTHONPATH=src python -m cbcli.main portfolio show
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main portfolio show
```

Example workflow:

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 100
PYTHONPATH=src python -m cbcli.main portfolio show
```

---

## 3. `market`

This is the main trading and market-inspection group.

### `market products`

Shows available products from the exchange.

Use cases:

* confirm valid product symbols
* browse tradable pairs
* confirm adapter connectivity

Examples:

```bash
PYTHONPATH=src python -m cbcli.main market products
PYTHONPATH=src python -m cbcli.main market products --limit 10
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main market products
```

### `market buy`

Places a market buy using a USD amount.

Use cases:

* buy fixed-dollar amounts of BTC, ETH, SOL
* quickly enter a position
* test paper execution flow

Examples:

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 100
PYTHONPATH=src python -m cbcli.main market buy SOL-USD --usd 50
```

With dry-run:

```bash
CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
```

With live mode:

```bash
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
```

With slippage reference price:

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25 --ref-price 85000
PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 100 --ref-price 2000
```

With max-order guard testing:

```bash
CBCLI_MAX_ORDER_USD=50 PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 100
```

### `market sell`

Places a market sell using base asset size.

Use cases:

* trim a position
* fully exit a position
* test sell logic in paper mode

Examples:

```bash
PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size 0.0001
PYTHONPATH=src python -m cbcli.main market sell ETH-USD --size 0.01
```

With dry-run:

```bash
CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size 0.0001
```

With slippage reference price:

```bash
PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size 0.0001 --ref-price 85000
```

Suggested safety workflow:

```bash
CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main market sell ETH-USD --size 0.01
CBCLI_MODE=paper PYTHONPATH=src python -m cbcli.main market sell ETH-USD --size 0.01
```

---

## 4. `orders`

Use this group to inspect and manage open orders.

### `orders list`

Shows open orders.

Use cases:

* inspect currently open limit orders
* verify whether a limit order was stored
* confirm paper or live open order state

Examples:

```bash
PYTHONPATH=src python -m cbcli.main orders list
CBCLI_MODE=paper PYTHONPATH=src python -m cbcli.main orders list
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main orders list
```

### `orders cancel`

Cancels an order by order ID.

Use cases:

* remove stale limit orders
* cancel a test order
* clean up paper/live order state

Examples:

```bash
PYTHONPATH=src python -m cbcli.main orders cancel 12345
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main orders cancel <order_id>
```

Typical workflow:

```bash
PYTHONPATH=src python -m cbcli.main orders list
PYTHONPATH=src python -m cbcli.main orders cancel <order_id>
PYTHONPATH=src python -m cbcli.main orders list
```

---

## 5. `watch`

Use this group to monitor prices repeatedly from the terminal.

### `watch ticker`

Polls and displays ticker prices for a product on an interval.

Use cases:

* watch BTC before entering
* monitor ETH while testing slippage guard
* keep a simple terminal price feed open

Examples:

```bash
PYTHONPATH=src python -m cbcli.main watch ticker BTC-USD
PYTHONPATH=src python -m cbcli.main watch ticker ETH-USD --interval 1.0
PYTHONPATH=src python -m cbcli.main watch ticker SOL-USD --interval 5.0
```

Stop with `Ctrl+C`.

---

# Common Workflows

## Workflow 1: safe paper buy test

```bash
CBCLI_MODE=paper PYTHONPATH=src python -m cbcli.main account balance
CBCLI_MODE=paper PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
CBCLI_MODE=paper PYTHONPATH=src python -m cbcli.main portfolio show
```

## Workflow 2: dry-run before a real trade

```bash
CBCLI_DRY_RUN=true CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25 --ref-price 85000
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main account balance
```

## Workflow 3: test max-order safety guard

```bash
CBCLI_MAX_ORDER_USD=50 PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 100
```

Expected idea:

* order should be rejected
* command should fail cleanly
* rejection should be journaled

## Workflow 4: inspect holdings after multiple buys

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 100
PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 100
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
```

## Workflow 5: watch first, then trade

```bash
PYTHONPATH=src python -m cbcli.main watch ticker BTC-USD --interval 1.0
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25 --ref-price 85000
```

---

# Environment Variable Cheat Sheet

## Mode selection

```bash
CBCLI_MODE=paper
CBCLI_MODE=live
```

## Dry run

```bash
CBCLI_DRY_RUN=true
CBCLI_DRY_RUN=false
```

## Max order size guard

```bash
CBCLI_MAX_ORDER_USD=50
CBCLI_MAX_ORDER_USD=250
```

## Slippage threshold

```bash
CBCLI_MAX_SLIPPAGE_PCT=0.005
```

## Example combined commands

```bash
CBCLI_MODE=paper CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
CBCLI_MODE=paper CBCLI_MAX_ORDER_USD=50 PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 100
CBCLI_MODE=live CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main account balance
```

---

# Quick Reminders

* `account balance` = raw balances
* `portfolio show` = holdings plus estimated USD value
* `market buy` uses `--usd`
* `market sell` uses `--size`
* `orders list` shows open orders
* `orders cancel` cancels by order ID
* `watch ticker` loops until stopped
* `CBCLI_MODE=live` means real account access
* `CBCLI_DRY_RUN=true` is your friend

---

# Good Habits

1. Test in paper mode first.
2. Use dry-run before live execution.
3. Use `--ref-price` when you want slippage protection.
4. Check `account balance` and `portfolio show` after trades.
5. Keep max-order guards low while developing.
6. Treat live mode as dangerous until confirmation prompts are added.

---

# Suggested commands to memorize first

```bash
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
PYTHONPATH=src python -m cbcli.main market products
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size 0.0001
PYTHONPATH=src python -m cbcli.main orders list
PYTHONPATH=src python -m cbcli.main watch ticker BTC-USD
CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
```
