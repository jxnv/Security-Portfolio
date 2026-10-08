import typer

from cbcli.cli.commands.account import app as account_app
from cbcli.cli.commands.portfolio import app as portfolio_app
from cbcli.cli.commands.orders import app as orders_app
from cbcli.cli.commands.market import app as market_app
from cbcli.cli.commands.watch import app as watch_app

app = typer.Typer(help="Coinbase CLI")

app.add_typer(account_app, name="account")
app.add_typer(portfolio_app, name="portfolio")
app.add_typer(orders_app, name="orders")
app.add_typer(market_app, name="market")
app.add_typer(watch_app, name="watch")