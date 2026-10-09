# Title: PST Export Alert Using eDiscovery Alert
# ID: 18b88d08-d73e-4f21-bc25-4b9892a4fdd0
# Status: test
# Level: medium
# Author: Sorina Ionescu
# Date: 2022-02-08
# Tags: attack.collection, attack.t1114
# Description: Alert on when a user has performed an eDiscovery search or exported a PST file from the search. This PST file usually has sensitive information including email body content
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PST Export Alert Using eDiscovery Alert
def rule(event):
    # Detection Logic:
    # (eventSource="SecurityComplianceCenter" AND eventName="eDiscovery search started or exported" AND status="success")
    return True

def title(event):
    return "PST Export Alert Using eDiscovery Alert"

