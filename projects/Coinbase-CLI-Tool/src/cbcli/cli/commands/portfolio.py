from rich.console import Console
import typer
from decimal import Decimal

from cbcli.core.bootstrap import build_services
from cbcli.ui.tables import positions_table

app = typer.Typer()
console = Console()


@app.command("show")
def show():
    services = build_services()
    portfolio_service = services["portfolio_service"]

    positions = portfolio_service.get_positions()
    total_usd = portfolio_service.get_total_usd_value()

    console.print(positions_table(positions, total_usd))

@app.command("exposure")
def exposure():
    services = build_services()
    svc = services["portfolio_intelligence_service"]

    report = svc.exposure_report()

    for asset, data in report.items():
        console.print(
            f"{asset}: ${data['usd_value']:.2f} ({data['pct']*100:.2f}%)"
        )


@app.command("allocation")
def allocation():
    services = build_services()
    svc = services["portfolio_intelligence_service"]

    target_alloc = {
        "BTC": Decimal("0.50"),
        "ETH": Decimal("0.30"),
        "USD": Decimal("0.20"),
    }

    report = svc.allocation_report(target_alloc)

    for row in report:
        console.print(
            f"{row['asset']}: current={row['current_pct']*100:.2f}% | "
            f"target={row['target_pct']*100:.2f}% | "
            f"diff={row['diff']*100:.2f}%"
        )