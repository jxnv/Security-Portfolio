# Title: OpenCanary - REDIS Action Command Attempt
# ID: 547dfc53-ebf6-4afe-8d2e-793d9574975d
# Status: test
# Level: high
# Author: Security Onion Solutions
# Date: 2024-03-08
# Tags: attack.credential-access, attack.collection, attack.t1003, attack.t1213
# Description: Detects instances where a REDIS service on an OpenCanary node has had an action command attempted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OpenCanary - REDIS Action Command Attempt
def rule(event):
    # Detection Logic:
    # (logtype="17001")
    return True

def title(event):
    return "OpenCanary - REDIS Action Command Attempt"

