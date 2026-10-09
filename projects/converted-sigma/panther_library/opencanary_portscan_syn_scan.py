# Title: OpenCanary - Host Port Scan (SYN Scan)
# ID: 974be8d2-283e-4033-ab08-7505b84204d0
# Status: experimental
# Level: high
# Author: Marco Pedrinazzi (@pedrinazziM)
# Date: 2026-01-06
# Tags: attack.discovery, attack.t1046
# Description: Detects instances where an OpenCanary node has been targeted by a SYN port scan.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OpenCanary - Host Port Scan (SYN Scan)
def rule(event):
    # Detection Logic:
    # (logtype="5001")
    return True

def title(event):
    return "OpenCanary - Host Port Scan (SYN Scan)"

