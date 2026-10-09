# Title: Azure Firewall Rule Collection Modified or Deleted
# ID: 025c9fe7-db72-49f9-af0d-31341dd7dd57
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-08-08
# Tags: attack.impact, attack.defense-impairment, attack.t1686.001
# Description: Identifies when Rule Collections (Application, NAT, and Network) is being modified or deleted.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure Firewall Rule Collection Modified or Deleted
def rule(event):
    # Detection Logic:
    # ((operationName="MICROSOFT.NETWORK/AZUREFIREWALLS/APPLICATIONRULECOLLECTIONS/WRITE" OR operationName="MICROSOFT.NETWORK/AZUREFIREWALLS/APPLICATIONRULECOLLECTIONS/DELETE" OR operationName="MICROSOFT.NETWORK/AZUREFIREWALLS/NATRULECOLLECTIONS/WRITE" OR operationName="MICROSOFT.NETWORK/AZUREFIREWALLS/NATRULECOLLECTIONS/DELETE" OR operationName="MICROSOFT.NETWORK/AZUREFIREWALLS/NETWORKRULECOLLECTIONS/WRITE" OR operationName="MICROSOFT.NETWORK/AZUREFIREWALLS/NETWORKRULECOLLECTIONS/DELETE"))
    return True

def title(event):
    return "Azure Firewall Rule Collection Modified or Deleted"

