# Title: Azure Application Security Group Modified or Deleted
# ID: 835747f1-9329-40b5-9cc3-97d465754ce6
# Status: test
# Level: medium
# Author: Austin Songer
# Date: 2021-08-16
# Tags: attack.impact
# Description: Identifies when a application security group is modified or deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure Application Security Group Modified or Deleted
def rule(event):
    # Detection Logic:
    # ((operationName="MICROSOFT.NETWORK/APPLICATIONSECURITYGROUPS/WRITE" OR operationName="MICROSOFT.NETWORK/APPLICATIONSECURITYGROUPS/DELETE"))
    return True

def title(event):
    return "Azure Application Security Group Modified or Deleted"

