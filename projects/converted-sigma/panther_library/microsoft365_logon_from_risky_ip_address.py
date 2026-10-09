# Title: Logon from a Risky IP Address
# ID: c191e2fa-f9d6-4ccf-82af-4f2aba08359f
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-08-23
# Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.stealth, attack.t1078
# Description: Detects when a Microsoft Cloud App Security reported when a user signs into your sanctioned apps from a risky IP address.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Logon from a Risky IP Address
def rule(event):
    # Detection Logic:
    # (eventSource="SecurityComplianceCenter" AND eventName="Log on from a risky IP address" AND status="success")
    return True

def title(event):
    return "Logon from a Risky IP Address"

