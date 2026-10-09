# Title: Azure Device No Longer Managed or Compliant
# ID: 542b9912-c01f-4e3f-89a8-014c48cdca7d
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-03
# Tags: attack.impact
# Description: Identifies when a device in azure is no longer managed or compliant
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure Device No Longer Managed or Compliant
def rule(event):
    # Detection Logic:
    # ((operationName="Device no longer compliant" OR operationName="Device no longer managed"))
    return True

def title(event):
    return "Azure Device No Longer Managed or Compliant"

