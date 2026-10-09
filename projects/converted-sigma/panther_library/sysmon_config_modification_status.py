# Title: Sysmon Configuration Modification
# ID: 1f2b5353-573f-4880-8e33-7d04dcf97744
# Status: test
# Level: high
# Author: frack113
# Date: 2021-06-04
# Tags: attack.stealth, attack.t1564
# Description: Detects when an attacker tries to hide from Sysmon by disabling or stopping it
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Sysmon Configuration Modification
def rule(event):
    # Detection Logic:
    # ((("Sysmon config state changed") OR (State="Stopped")) AND NOT ((State="Started")))
    return True

def title(event):
    return "Sysmon Configuration Modification"

