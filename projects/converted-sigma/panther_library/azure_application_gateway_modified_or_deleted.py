# Title: Azure Application Gateway Modified or Deleted
# ID: ad87d14e-7599-4633-ba81-aeb60cfe8cd6
# Status: test
# Level: medium
# Author: Austin Songer
# Date: 2021-08-16
# Tags: attack.impact
# Description: Identifies when a application gateway is modified or deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure Application Gateway Modified or Deleted
def rule(event):
    # Detection Logic:
    # ((operationName="MICROSOFT.NETWORK/APPLICATIONGATEWAYS/WRITE" OR operationName="MICROSOFT.NETWORK/APPLICATIONGATEWAYS/DELETE"))
    return True

def title(event):
    return "Azure Application Gateway Modified or Deleted"

