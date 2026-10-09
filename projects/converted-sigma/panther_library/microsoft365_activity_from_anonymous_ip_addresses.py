# Title: Activity from Anonymous IP Addresses
# ID: d8b0a4fe-07a8-41be-bd39-b14afa025d95
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-08-23
# Tags: attack.command-and-control, attack.t1573
# Description: Detects when a Microsoft Cloud App Security reported when users were active from an IP address that has been identified as an anonymous proxy IP address.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Activity from Anonymous IP Addresses
def rule(event):
    # Detection Logic:
    # (eventSource="SecurityComplianceCenter" AND eventName="Activity from anonymous IP addresses" AND status="success")
    return True

def title(event):
    return "Activity from Anonymous IP Addresses"

