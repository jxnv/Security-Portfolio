# Title: Okta Network Zone Deactivated or Deleted
# ID: 9f308120-69ed-4506-abde-ac6da81f4310
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-12
# Tags: attack.impact
# Description: Detects when an Network Zone is Deactivated or Deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta Network Zone Deactivated or Deleted
def rule(event):
    # Detection Logic:
    # ((eventType="zone.deactivate" OR eventType="zone.delete"))
    return True

def title(event):
    return "Okta Network Zone Deactivated or Deleted"

