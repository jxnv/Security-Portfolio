# Title: OpenCanary - SSH Login Attempt
# ID: ff7139bc-fdb1-4437-92f2-6afefe8884cb
# Status: test
# Level: high
# Author: Security Onion Solutions
# Date: 2024-03-08
# Tags: attack.privilege-escalation, attack.initial-access, attack.lateral-movement, attack.persistence, attack.stealth, attack.t1133, attack.t1021, attack.t1078
# Description: Detects instances where an SSH service on an OpenCanary node has had a login attempt.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OpenCanary - SSH Login Attempt
def rule(event):
    # Detection Logic:
    # (logtype="4002")
    return True

def title(event):
    return "OpenCanary - SSH Login Attempt"

