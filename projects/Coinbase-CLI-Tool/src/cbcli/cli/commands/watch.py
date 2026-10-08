import time

from rich.console import Console
import typer

from cbcli.core.bootstrap import build_services

app = typer.Typer()
console = Console()


@app.command("ticker")
def ticker(product_id: str, interval: float = 2.0):
    services = build_services()
    exchange = services["exchange"]

    console.print(f"Watching {product_id} every {interval} seconds. Ctrl+C to stop.")
    try:
        while True:
            tick = exchange.get_ticker(product_id)
            console.print(f"{tick.product_id}: {tick.price}")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("Stopped.")