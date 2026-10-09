# Title: Okta API Token Created
# ID: 19951c21-229d-4ccb-8774-b993c3ff3c5c
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-12
# Tags: attack.persistence
# Description: Detects when a API token is created
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta API Token Created
def rule(event):
    # Detection Logic:
    # (eventType="system.api_token.create")
    return True

def title(event):
    return "Okta API Token Created"

