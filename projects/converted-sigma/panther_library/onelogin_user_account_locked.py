# Title: OneLogin User Account Locked
# ID: a717c561-d117-437e-b2d9-0118a7035d01
# Status: test
# Level: low
# Author: Austin Songer @austinsonger
# Date: 2021-10-12
# Tags: attack.impact
# Description: Detects when an user account is locked or suspended.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OneLogin User Account Locked
def rule(event):
    # Detection Logic:
    # ((event_type_id="532") OR (event_type_id="553") OR (event_type_id="551"))
    return True

def title(event):
    return "OneLogin User Account Locked"

