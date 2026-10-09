# Title: OneLogin User Assumed Another User
# ID: 62fff148-278d-497e-8ecd-ad6083231a35
# Status: test
# Level: low
# Author: Austin Songer @austinsonger
# Date: 2021-10-12
# Tags: attack.impact
# Description: Detects when an user assumed another user account.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: OneLogin User Assumed Another User
def rule(event):
    # Detection Logic:
    # (event_type_id="3")
    return True

def title(event):
    return "OneLogin User Assumed Another User"

