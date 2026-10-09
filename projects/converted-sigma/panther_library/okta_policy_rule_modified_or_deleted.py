# Title: Okta Policy Rule Modified or Deleted
# ID: 0c97c1d3-4057-45c9-b148-1de94b631931
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-12
# Tags: attack.impact
# Description: Detects when an Policy Rule is Modified or Deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta Policy Rule Modified or Deleted
def rule(event):
    # Detection Logic:
    # ((eventType="policy.rule.update" OR eventType="policy.rule.delete"))
    return True

def title(event):
    return "Okta Policy Rule Modified or Deleted"

