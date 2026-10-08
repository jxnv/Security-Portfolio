Yes — before Phase 5, you should absolutely **stress test the whole CLI like a hostile user would**.

Do it in layers:

## 1. Clean reset first

From project root:

```bash
rm -f paper_state.json cbcli.db
```

Then confirm fresh state:

```bash
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
```

You should see fresh paper cash and no crypto holdings.

---

## 2. Core command sanity checks

### Balance / portfolio / products

```bash
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
PYTHONPATH=src python -m cbcli.main market products 
PYTHONPATH=src python -m cbcli.main market products 
PYTHONPATH=src python -m cbcli.main watch ticker BTC-USD --interval 2 
```

Stop watch with `Ctrl+C`.

### Market buy / sell basic flow

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 50
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
PYTHONPATH=src python -m cbcli.main market sell ETH-USD --size 0.01
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
```

This checks:

* command parsing
* order building
* execution service
* paper adapter persistence
* portfolio calculation

---

## 3. Persistence tests

These matter a lot because CLI tools restart each run.

### Buy, exit shell mentally, re-run

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 100
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
```

Run the same two read commands again:

```bash
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
```

Values should stay the same.

### Multiple sequential buys

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
PYTHONPATH=src python -m cbcli.main portfolio show
```

This checks accumulation.

---

## 4. Input validation tests

### Negative and zero values

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 0
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd -5
PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size 0
PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size -0.01
```

Expected:

* clean failure
* no traceback
* no state change

### Bad numeric input

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd abc
PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size nope
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25 --ref-price bad
```

Expected:

* `BadParameter` style message
* no crash

### Unknown product

```bash
PYTHONPATH=src python -m cbcli.main market buy FAKE-USD --usd 25
PYTHONPATH=src python -m cbcli.main watch ticker FAKE-USD
```

Expected:

* clean failure
* no silent success

---

## 5. Risk guard tests

### Dry run

```bash
CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
```

Expected:

* order says `DRY_RUN`
* balances unchanged

### Max order guard

```bash
CBCLI_MAX_ORDER_USD=50 PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 100
```

Expected:

* rejected cleanly
* no traceback
* no balance change

### Slippage guard pass

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25 --ref-price 85000
```

Expected:

* should pass in paper if BTC mock is 85000

### Slippage guard fail

```bash
CBCLI_MAX_SLIPPAGE_PCT=0.001 PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25 --ref-price 80000
```

Expected:

* rejected for slippage

---

## 6. Insufficient funds / insufficient asset tests

### Overspend cash

```bash
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 999999
```

Expected:

* failure
* no broken state

### Sell more than owned

```bash
PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size 99
```

Expected:

* failure
* no negative holdings

---

## 7. Orders subsystem tests

If limit order commands already exist, test them. If not, skip for now.

### Open orders read path

```bash
PYTHONPATH=src python -m cbcli.main orders list XXXXXbroken
```

### Cancel bogus order

```bash
PYTHONPATH=src python -m cbcli.main orders cancel not-a-real-order-id
```

Expected:

* graceful “not found” style response

If you do have limit order creation later, test:

```bash
PYTHONPATH=src python -m cbcli.main orders list 
PYTHONPATH=src python -m cbcli.main orders cancel <real_order_id>
PYTHONPATH=src python -m cbcli.main orders list
```

---

## 8. Journal / SQLite tests

### Inspect database file exists

```bash
ls -lh cbcli.db
```

### Show recent journal rows

```bash
sqlite3 cbcli.db "select id, ts, mode, dry_run, product_id, side, order_type, status, success, error_message from trade_journal order by id desc limit 20;"
```

### Count successes vs failures

```bash
sqlite3 cbcli.db "select status, success, count(*) from trade_journal group by status, success order by count(*) desc;"
```

### Check dry-run rows

```bash
sqlite3 cbcli.db "select id, ts, dry_run, product_id, status from trade_journal where dry_run = 1 order by id desc limit 10;"
```

You want to confirm:

* successful orders logged
* rejected orders logged
* dry runs logged

---

## 9. Portfolio intelligence tests

### Exposure / allocation

```bash
PYTHONPATH=src python -m cbcli.main portfolio exposure
PYTHONPATH=src python -m cbcli.main portfolio allocation
```

### Build a mixed portfolio first

```bash
rm -f paper_state.json cbcli.db
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 150
PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 300
PYTHONPATH=src python -m cbcli.main market buy SOL-USD --usd 50
PYTHONPATH=src python -m cbcli.main portfolio show
PYTHONPATH=src python -m cbcli.main portfolio exposure
PYTHONPATH=src python -m cbcli.main portfolio allocation
```

This helps verify:

* percentages look sane
* larger positions rank higher
* target comparison logic behaves as expected

### PnL tests

If PnL command exists:

```bash
PYTHONPATH=src python -m cbcli.main portfolio pnl XX pnl broken
```

Then move mock prices in paper adapter and rerun. For example, temporarily change:

* BTC from 85000 to 90000
* ETH from 2000 to 1800

Then rerun:

```bash
PYTHONPATH=src python -m cbcli.main portfolio pnl XXX pnl broken
```

This checks unrealized PnL direction.

---

## 10. Live mode non-trading safety checks

Do **read-only** live tests first.

### Account balance

```bash
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main account balance
```

### Portfolio read path

```bash
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main portfolio show
```

### Products read path

```bash
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main market products --limit 5
```

### Ticker read path

```bash
CBCLI_MODE=live PYTHONPATH=src python -m cbcli.main watch ticker BTC-USD --interval 2 broken 
```

Only after those pass would I test:

```bash
CBCLI_MODE=live CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25 real purchase
```

I would **not** do live non-dry-run stress tests yet.

---

## 11. Regression checklist

After all tests, confirm these still work:

```bash
PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size 0.0001
PYTHONPATH=src python -m cbcli.main portfolio exposure
PYTHONPATH=src python -m cbcli.main portfolio allocation
sqlite3 cbcli.db "select count(*) from trade_journal;"
```

---

## 12. Best “full gauntlet” sequence

Run this in order for a strong end-to-end test:

```bash
rm -f paper_state.json cbcli.db

PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
PYTHONPATH=src python -m cbcli.main market products --limit 5 broken

CBCLI_DRY_RUN=true PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25
PYTHONPATH=src python -m cbcli.main account balance

PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 100
PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 150
PYTHONPATH=src python -m cbcli.main market sell ETH-USD --size 0.01

PYTHONPATH=src python -m cbcli.main account balance
PYTHONPATH=src python -m cbcli.main portfolio show
PYTHONPATH=src python -m cbcli.main portfolio exposure
PYTHONPATH=src python -m cbcli.main portfolio allocation

CBCLI_MAX_ORDER_USD=50 PYTHONPATH=src python -m cbcli.main market buy ETH-USD --usd 100
CBCLI_MAX_SLIPPAGE_PCT=0.001 PYTHONPATH=src python -m cbcli.main market buy BTC-USD --usd 25 --ref-price 80000
PYTHONPATH=src python -m cbcli.main market sell BTC-USD --size 999

sqlite3 cbcli.db "select id, ts, product_id, side, status, success, error_message from trade_journal order by id desc limit 20;"
```

---

## What “passing” looks like

You’re in good shape if:

* no unexpected tracebacks
* bad inputs fail cleanly
* dry-run never changes balances
* paper trades persist across commands
* rejected orders get journaled
* exposure/allocation numbers are sane
* live read-only commands work

If you want, paste the results of the full gauntlet and I’ll audit them like a QA pass.
