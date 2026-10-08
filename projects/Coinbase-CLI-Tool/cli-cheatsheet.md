# cbcli Quick Cheat Sheet

## Core Pattern

```bash
PYTHONPATH=src python -m cbcli.main <group> <command>
```

---

## Must-Know Commands

### Balances

```bash
python -m cbcli.main account balance
```

### Portfolio

```bash
python -m cbcli.main portfolio show
```

### Buy

```bash
python -m cbcli.main market buy BTC-USD --usd 25
```

### Sell

```bash
python -m cbcli.main market sell BTC-USD --size 0.0001
```

### Products

```bash
python -m cbcli.main market products
```

### Orders

```bash
python -m cbcli.main orders list
python -m cbcli.main orders cancel <order_id>
```

### Watch Price

```bash
python -m cbcli.main watch ticker BTC-USD
```

---

## Modes

### Paper (SAFE)

```bash
CBCLI_MODE=paper
```

### Live (REAL MONEY)

```bash
CBCLI_MODE=live
```

### Dry Run (NO EXECUTION)

```bash
CBCLI_DRY_RUN=true
```

---

## Common Combos

### Safe test trade

```bash
CBCLI_MODE=paper python -m cbcli.main market buy BTC-USD --usd 25
```

### Dry-run before live

```bash
CBCLI_MODE=live CBCLI_DRY_RUN=true python -m cbcli.main market buy BTC-USD --usd 25
```

### With slippage protection

```bash
python -m cbcli.main market buy BTC-USD --usd 25 --ref-price 85000
```

### Test max order guard

```bash
CBCLI_MAX_ORDER_USD=50 python -m cbcli.main market buy ETH-USD --usd 100
```

---

## Mental Model

* `account` → balances
* `portfolio` → holdings + value
* `market buy` → use USD
* `market sell` → use asset size
* `orders` → manage open orders
* `watch` → live ticker loop

---

## Safety Rules

* Always test in **paper** first
* Use **dry-run** before live
* Keep **max order low** while developing
* Double check before using `live`

---

## Fast Start (copy this)

```bash
CBCLI_MODE=paper python -m cbcli.main account balance
CBCLI_MODE=paper python -m cbcli.main market buy BTC-USD --usd 25
CBCLI_MODE=paper python -m cbcli.main portfolio show
```
