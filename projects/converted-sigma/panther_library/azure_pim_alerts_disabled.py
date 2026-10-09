# Title: PIM Alert Setting Changes To Disabled
# ID: aeaef14c-e5bf-4690-a9c8-835caad458bd
# Status: test
# Level: high
# Author: Mark Morowczynski '@markmorow', Yochana Henderson, '@Yochana-H'
# Date: 2022-08-09
# Tags: attack.initial-access, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1078
# Description: Detects when PIM alerts are set to disabled.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PIM Alert Setting Changes To Disabled
def rule(event):
    # Detection Logic:
    # (properties.message="Disable PIM Alert")
    return True

def title(event):
    return "PIM Alert Setting Changes To Disabled"

