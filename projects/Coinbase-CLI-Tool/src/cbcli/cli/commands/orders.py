from rich.console import Console
import typer

from cbcli.core.bootstrap import build_services
from cbcli.ui.tables import orders_table

app = typer.Typer()
console = Console()


@app.command("list")
def list_orders():
    services = build_services()
    orders = services["order_service"].list_open_orders(services["exchange"])
    console.print(orders_table(orders))


@app.command("cancel")
def cancel(order_id: str):
    services = build_services()
    ok = services["order_service"].cancel_order(services["exchange"], order_id)
    if ok:
        console.print(f"[green]Cancelled[/green] {order_id}")
    else:
        console.print(f"[red]Order not found or cancel failed[/red] {order_id}")