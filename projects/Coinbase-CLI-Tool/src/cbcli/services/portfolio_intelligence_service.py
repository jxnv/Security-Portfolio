from __future__ import annotations

from decimal import Decimal


class PortfolioIntelligenceService:
    def __init__(self, exchange):
        self.exchange = exchange

    def exposure_report(self):
        accounts = self.exchange.list_accounts()

        total_usd = Decimal("0")
        asset_values = {}

        for acc in accounts:
            if acc.currency == "USD":
                total_usd += acc.total_balance
            else:
                product = f"{acc.currency}-USD"

                try:
                    ticker = self.exchange.get_ticker(product)
                    value = acc.total_balance * ticker.price
                except Exception:
                    # Skip assets that don't have a USD pair
                    continue

                asset_values[acc.currency] = value
                total_usd += value

        report = {}

        for asset, value in asset_values.items():
            report[asset] = {
                "usd_value": value,
                "pct": value / total_usd if total_usd > 0 else Decimal("0"),
            }

        return report

    def allocation_report(self, target_alloc):
        exposure = self.exposure_report()
        result = []

        for asset, data in exposure.items():
            current_pct = data["pct"]
            target_pct = target_alloc.get(asset, Decimal("0"))
            diff = current_pct - target_pct

            result.append({
                "asset": asset,
                "current_pct": current_pct,
                "target_pct": target_pct,
                "diff": diff,
            })

        return sorted(result, key=lambda x: x["diff"], reverse=True)