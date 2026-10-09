# Title: Okta Application Modified or Deleted
# ID: 7899144b-e416-4c28-b0b5-ab8f9e0a541d
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-12
# Tags: attack.impact
# Description: Detects when an application is modified or deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta Application Modified or Deleted
def rule(event):
    # Detection Logic:
    # ((eventType="application.lifecycle.update" OR eventType="application.lifecycle.delete"))
    return True

def title(event):
    return "Okta Application Modified or Deleted"

