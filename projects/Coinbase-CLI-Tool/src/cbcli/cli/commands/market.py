from decimal import Decimal, InvalidOperation

from rich.console import Console
from cbcli.core.exceptions import CBCLIError
import typer

from cbcli.core.bootstrap import build_services

app = typer.Typer()
console = Console()


@app.command("buy")
def buy(
    product_id: str,
    usd: str = typer.Option(..., "--usd"),
    ref_price: str | None = typer.Option(None, "--ref-price"),
):
    try:
        usd_amount = Decimal(usd)
        ref_price_dec = Decimal(ref_price) if ref_price is not None else None
    except InvalidOperation:
        raise typer.BadParameter("Invalid numeric input")

    services = build_services()

    try:
        order = services["order_service"].build_market_buy_by_quote(product_id, usd_amount)
        result = services["execution_service"].execute_order(order, reference_price=ref_price_dec)

        if result.success:
            console.print(
                f"[green]{result.status}[/green] {product_id} | "
                f"client_order_id={result.client_order_id} | order_id={result.order_id}"
            )
        else:
            console.print(f"[red]BUY failed[/red] {result.error_message}")

    except CBCLIError as exc:
        console.print(f"[red]BUY failed[/red] {exc}")
        raise typer.Exit(code=1)


@app.command("sell")
def sell(
    product_id: str,
    size: str = typer.Option(..., "--size"),
    ref_price: str | None = typer.Option(None, "--ref-price"),
):
    try:
        base_size = Decimal(size)
        ref_price_dec = Decimal(ref_price) if ref_price is not None else None
    except InvalidOperation:
        raise typer.BadParameter("Invalid numeric input")

    services = build_services()

    try:
        order = services["order_service"].build_market_sell_by_base(product_id, base_size)
        result = services["execution_service"].execute_order(order, reference_price=ref_price_dec)

        if result.success:
            console.print(
                f"[green]{result.status}[/green] {product_id} | "
                f"client_order_id={result.client_order_id} | order_id={result.order_id}"
            )
        else:
            console.print(f"[red]SELL failed[/red] {result.error_message}")

    except CBCLIError as exc:
        console.print(f"[red]SELL failed[/red] {exc}")
        raise typer.Exit(code=1)


@app.command("products")
def products(limit: int = 10):
    services = build_services()
    exchange = services["exchange"]

    products = exchange.list_products()

    for p in products[:limit]:
        console.print(f"{p.product_id} | {p.base_currency}/{p.quote_currency}")