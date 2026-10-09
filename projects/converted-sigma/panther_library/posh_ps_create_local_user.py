# Title: PowerShell Create Local User
# ID: 243de76f-4725-4f2e-8225-a8a69b15ad61
# Status: test
# Level: medium
# Author: @ROxPinTeddy
# Date: 2020-04-11
# Tags: attack.execution, attack.t1059.001, attack.persistence, attack.t1136.001
# Description: Detects creation of a local user via PowerShell
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PowerShell Create Local User
def rule(event):
    # Detection Logic:
    # (ScriptBlockText="*New-LocalUser*")
    return True

def title(event):
    return "PowerShell Create Local User"

