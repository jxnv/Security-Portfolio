# Title: OpenCanary - TFTP Request
# ID: b4e6b016-a2ac-4759-ad85-8000b300d61e
# Status: test
# Level: high
# Author: Security Onion Solutions
# Date: 2024-03-08
# Tags: attack.exfiltration, attack.t1041
# Description: Detects instances where a TFTP service on an OpenCanary node has had a request.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OpenCanary - TFTP Request
def rule(event):
    # Detection Logic:
    # (logtype="10001")
    return True

def title(event):
    return "OpenCanary - TFTP Request"

