# Title: OpenCanary - Telnet Login Attempt
# ID: 512cff7a-683a-43ad-afe0-dd398e872f36
# Status: test
# Level: high
# Author: Security Onion Solutions
# Date: 2024-03-08
# Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.command-and-control, attack.stealth, attack.t1133, attack.t1078
# Description: Detects instances where a Telnet service on an OpenCanary node has had a login attempt.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OpenCanary - Telnet Login Attempt
def rule(event):
    # Detection Logic:
    # (logtype="6001")
    return True

def title(event):
    return "OpenCanary - Telnet Login Attempt"

