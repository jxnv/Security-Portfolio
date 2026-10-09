# Title: Okta Policy Modified or Deleted
# ID: 1667a172-ed4c-463c-9969-efd92195319a
# Status: test
# Level: low
# Author: Austin Songer @austinsonger
# Date: 2021-09-12
# Tags: attack.impact
# Description: Detects when an Okta policy is modified or deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta Policy Modified or Deleted
def rule(event):
    # Detection Logic:
    # ((eventType="policy.lifecycle.update" OR eventType="policy.lifecycle.delete"))
    return True

def title(event):
    return "Okta Policy Modified or Deleted"

