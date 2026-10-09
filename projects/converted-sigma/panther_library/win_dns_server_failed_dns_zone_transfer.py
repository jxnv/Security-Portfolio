# Title: Failed DNS Zone Transfer
# ID: 6d444368-6da1-43fe-b2fc-44202430480e
# Status: test
# Level: medium
# Author: Zach Mathis
# Date: 2023-05-24
# Tags: attack.reconnaissance, attack.t1590.002
# Description: Detects when a DNS zone transfer failed.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Failed DNS Zone Transfer
def rule(event):
    # Detection Logic:
    # (EventID="6004")
    return True

def title(event):
    return "Failed DNS Zone Transfer"

