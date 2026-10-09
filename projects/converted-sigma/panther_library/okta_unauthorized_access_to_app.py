# Title: Okta Unauthorized Access to App
# ID: 6cc2b61b-d97e-42ef-a9dd-8aa8dc951657
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-12
# Tags: attack.impact
# Description: Detects when unauthorized access to app occurs.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta Unauthorized Access to App
def rule(event):
    # Detection Logic:
    # (displayMessage="User attempted unauthorized access to app")
    return True

def title(event):
    return "Okta Unauthorized Access to App"

