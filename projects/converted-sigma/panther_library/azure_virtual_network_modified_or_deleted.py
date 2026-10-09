# Title: Azure Virtual Network Modified or Deleted
# ID: bcfcc962-0e4a-4fd9-84bb-a833e672df3f
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-08-08
# Tags: attack.impact
# Description: Identifies when a Virtual Network is modified or deleted in Azure.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure Virtual Network Modified or Deleted
def rule(event):
    # Detection Logic:
    # ((operationName="MICROSOFT.NETWORK/VIRTUALNETWORKGATEWAYS/*" OR operationName="MICROSOFT.NETWORK/VIRTUALNETWORKS/*") AND (operationName="*/WRITE" OR operationName="*/DELETE"))
    return True

def title(event):
    return "Azure Virtual Network Modified or Deleted"

