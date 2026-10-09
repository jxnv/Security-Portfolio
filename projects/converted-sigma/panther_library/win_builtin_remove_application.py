# Title: Application Uninstalled
# ID: 570ae5ec-33dc-427c-b815-db86228ad43e
# Status: test
# Level: low
# Author: frack113
# Date: 2022-01-28
# Tags: attack.impact, attack.t1489
# Description: An application has been removed. Check if it is critical.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Application Uninstalled
def rule(event):
    # Detection Logic:
    # (Provider_Name="MsiInstaller" AND (EventID="1034" OR EventID="11724"))
    return True

def title(event):
    return "Application Uninstalled"

