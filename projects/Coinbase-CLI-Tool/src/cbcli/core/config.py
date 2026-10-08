from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from cbcli.core.enums import EnvironmentMode
from cbcli.core.exceptions import ConfigurationError

load_dotenv()


@dataclass(slots=True)
class Settings:
    mode: EnvironmentMode
    profile: str
    dry_run: bool
    cdp_api_key_path: Path
    db_path: Path
    log_level: str = "INFO"
    default_quote_currency: str = "USD"
    paper_starting_cash: float = 10000.0
    max_order_usd: float = 250.0
    max_position_pct: float = 0.20
    max_slippage_pct: float = 0.005


def _resolve_path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _parse_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_settings() -> Settings:
    mode_raw = os.getenv("CBCLI_MODE", "paper").strip().lower()
    try:
        mode = EnvironmentMode(mode_raw)
    except ValueError as exc:
        raise ConfigurationError(
            f"Invalid CBCLI_MODE={mode_raw!r}. Expected 'paper' or 'live'."
        ) from exc

    return Settings(
        mode=mode,
        profile=os.getenv("CBCLI_PROFILE", "default"),
        dry_run=_parse_bool(os.getenv("CBCLI_DRY_RUN", "false")),
        cdp_api_key_path=_resolve_path(os.getenv("CDP_API_KEY_PATH", "./cdp_api_key.json")),
        db_path=_resolve_path(os.getenv("CBCLI_DB_PATH", "./cbcli.db")),
        log_level=os.getenv("CBCLI_LOG_LEVEL", "INFO"),
        default_quote_currency=os.getenv("CBCLI_DEFAULT_QUOTE", "USD"),
        paper_starting_cash=float(os.getenv("CBCLI_PAPER_STARTING_CASH", "10000")),
        max_order_usd=float(os.getenv("CBCLI_MAX_ORDER_USD", "250")),
        max_position_pct=float(os.getenv("CBCLI_MAX_POSITION_PCT", "0.20")),
        max_slippage_pct=float(os.getenv("CBCLI_MAX_SLIPPAGE_PCT", "0.005")),
    )


def load_cdp_api_key_file(path: Path) -> tuple[str, str]:
    if not path.exists():
        raise ConfigurationError(f"CDP API key file not found: {path}")

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"Invalid JSON in CDP API key file: {path}") from exc

    api_key = data.get("name")
    api_secret = data.get("privateKey")

    if not api_key or not api_secret:
        raise ConfigurationError(
            "CDP API key file must contain 'name' and 'privateKey'."
        )

    return api_key, api_secret