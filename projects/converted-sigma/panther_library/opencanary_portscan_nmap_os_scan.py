# Title: OpenCanary - NMAP OS Scan
# ID: e8a677fd-248c-4eab-94df-de2f6f645884
# Status: experimental
# Level: high
# Author: Marco Pedrinazzi (@pedrinazziM)
# Date: 2026-01-06
# Tags: attack.discovery, attack.t1046
# Description: Detects instances where an OpenCanary node has been targeted by a NMAP OS Scan
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OpenCanary - NMAP OS Scan
def rule(event):
    # Detection Logic:
    # (logtype="5002")
    return True

def title(event):
    return "OpenCanary - NMAP OS Scan"

