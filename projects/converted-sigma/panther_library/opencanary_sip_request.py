# Title: OpenCanary - SIP Request
# ID: e30de276-68ec-435c-ab99-ef3befec6c61
# Status: test
# Level: high
# Author: Security Onion Solutions
# Date: 2024-03-08
# Tags: attack.collection, attack.t1123
# Description: Detects instances where an SIP service on an OpenCanary node has had a SIP request.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OpenCanary - SIP Request
def rule(event):
    # Detection Logic:
    # (logtype="15001")
    return True

def title(event):
    return "OpenCanary - SIP Request"

