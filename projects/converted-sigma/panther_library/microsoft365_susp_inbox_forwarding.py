# Title: Suspicious Inbox Forwarding
# ID: 6c220477-0b5b-4b25-bb90-66183b4089e8
# Status: test
# Level: low
# Author: Austin Songer @austinsonger
# Date: 2021-08-22
# Tags: attack.exfiltration, attack.t1020
# Description: Detects when a Microsoft Cloud App Security reported suspicious email forwarding rules, for example, if a user created an inbox rule that forwards a copy of all emails to an external address.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Inbox Forwarding
def rule(event):
    # Detection Logic:
    # (eventSource="SecurityComplianceCenter" AND eventName="Suspicious inbox forwarding" AND status="success")
    return True

def title(event):
    return "Suspicious Inbox Forwarding"

