from rich.console import Console
import typer

from cbcli.core.bootstrap import build_services
from cbcli.ui.tables import accounts_table

app = typer.Typer()
console = Console()


@app.command("balance")
def balance():
    services = build_services()
    accounts = services["account_service"].get_nonzero_accounts()
    console.print(accounts_table(accounts))