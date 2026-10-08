from rich.table import Table


def accounts_table(accounts):
    table = Table(title="Balances")
    table.add_column("Currency")
    table.add_column("Available", justify="right")
    table.add_column("Hold", justify="right")
    table.add_column("Total", justify="right")

    for acct in accounts:
        table.add_row(
            acct.currency,
            str(acct.available_balance),
            str(acct.hold_balance),
            str(acct.total_balance),
        )
    return table


def positions_table(positions, total_usd):
    table = Table(title="Portfolio")
    table.add_column("Asset")
    table.add_column("Quantity", justify="right")
    table.add_column("USD Value", justify="right")

    for pos in positions:
        table.add_row(
            pos.asset,
            str(pos.quantity),
            "-" if pos.usd_value is None else f"{pos.usd_value:.2f}",
        )

    table.add_row("", "", "")
    table.add_row("TOTAL", "", f"{total_usd:.2f}")
    return table


def orders_table(orders):
    table = Table(title="Open Orders")
    table.add_column("Order ID")
    table.add_column("Product")
    table.add_column("Side")
    table.add_column("Type")
    table.add_column("Status")

    for order in orders:
        table.add_row(
            str(order.order_id or ""),
            str(order.product_id or ""),
            str(order.side.value if order.side else ""),
            str(order.order_type.value if order.order_type else ""),
            str(order.status or ""),
        )
    return table


def products_table(products):
    table = Table(title="Products")
    table.add_column("Product")
    table.add_column("Base")
    table.add_column("Quote")
    table.add_column("Price", justify="right")
    table.add_column("Status")

    for product in products:
        table.add_row(
            product.product_id,
            product.base_currency,
            product.quote_currency,
            "-" if product.price is None else str(product.price),
            str(product.status or ""),
        )
    return table