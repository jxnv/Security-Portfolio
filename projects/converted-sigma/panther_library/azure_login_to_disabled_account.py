# Title: Login to Disabled Account
# ID: 908655e0-25cf-4ae1-b775-1c8ce9cf43d8
# Status: test
# Level: medium
# Author: AlertIQ
# Date: 2021-10-10
# Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.stealth, attack.t1078.004
# Description: Detect failed attempts to sign in to disabled accounts.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Login to Disabled Account
def rule(event):
    # Detection Logic:
    # (ResultType="50057" AND ResultDescription="User account is disabled. The account has been disabled by an administrator.")
    return True

def title(event):
    return "Login to Disabled Account"

