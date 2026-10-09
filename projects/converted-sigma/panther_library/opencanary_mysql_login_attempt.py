# Title: OpenCanary - MySQL Login Attempt
# ID: e7d79a1b-25ed-4956-bd56-bd344fa8fd06
# Status: test
# Level: high
# Author: Security Onion Solutions
# Date: 2024-03-08
# Tags: attack.credential-access, attack.collection, attack.t1003, attack.t1213
# Description: Detects instances where a MySQL service on an OpenCanary node has had a login attempt.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OpenCanary - MySQL Login Attempt
def rule(event):
    # Detection Logic:
    # (logtype="8001")
    return True

def title(event):
    return "OpenCanary - MySQL Login Attempt"

