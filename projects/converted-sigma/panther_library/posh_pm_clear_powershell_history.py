# Title: Clear PowerShell History - PowerShell Module
# ID: f99276ad-d122-4989-a09a-d00904a5f9d2
# Status: test
# Level: medium
# Author: Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
# Date: 2019-10-25
# Tags: attack.stealth, attack.t1070.003
# Description: Detects keywords that could indicate clearing PowerShell history
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Clear PowerShell History - PowerShell Module
def rule(event):
    # Detection Logic:
    # ((((Payload="*Set-PSReadlineOption*" AND Payload="*–HistorySaveStyle*" AND Payload="*SaveNothing*")) OR ((Payload="*Set-PSReadlineOption*" AND Payload="*-HistorySaveStyle*" AND Payload="*SaveNothing*"))) OR (((Payload="*del*" OR Payload="*Remove-Item*" OR Payload="*rm*")) AND (Payload="*(Get-PSReadlineOption).HistorySavePath*")))
    return True

def title(event):
    return "Clear PowerShell History - PowerShell Module"

