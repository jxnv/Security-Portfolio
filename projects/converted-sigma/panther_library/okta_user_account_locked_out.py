# Title: Okta User Account Locked Out
# ID: 14701da0-4b0f-4ee6-9c95-2ffb4e73bb9a
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-12
# Tags: attack.impact, attack.t1531
# Description: Detects when an user account is locked out.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta User Account Locked Out
def rule(event):
    # Detection Logic:
    # (displayMessage="Max sign in attempts exceeded")
    return True

def title(event):
    return "Okta User Account Locked Out"

