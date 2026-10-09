# Title: Azure Network Security Configuration Modified or Deleted
# ID: d22b4df4-5a67-4859-a578-8c9a0b5af9df
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-08-08
# Tags: attack.impact
# Description: Identifies when a network security configuration is modified or deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure Network Security Configuration Modified or Deleted
def rule(event):
    # Detection Logic:
    # ((operationName="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE" OR operationName="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE" OR operationName="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE" OR operationName="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE" OR operationName="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/JOIN/ACTION" OR operationName="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/PROVIDERS/MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE"))
    return True

def title(event):
    return "Azure Network Security Configuration Modified or Deleted"

