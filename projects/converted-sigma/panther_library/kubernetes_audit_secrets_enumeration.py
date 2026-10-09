# Title: Kubernetes Secrets Enumeration
# ID: eeb3e9e1-b685-44e4-9232-6bb701f925b5
# Status: test
# Level: low
# Author: Leo Tsaousis (@laripping)
# Date: 2024-03-26
# Tags: attack.t1552.007, attack.credential-access
# Description: Detects enumeration of Kubernetes secrets.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Kubernetes Secrets Enumeration
def rule(event):
    # Detection Logic:
    # (verb="list" AND objectRef.resource="secrets")
    return True

def title(event):
    return "Kubernetes Secrets Enumeration"

