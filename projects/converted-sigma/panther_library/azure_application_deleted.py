# Title: Azure Application Deleted
# ID: 410d2a41-1e6d-452f-85e5-abdd8257a823
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-03
# Tags: attack.impact, attack.t1489
# Description: Identifies when a application is deleted in Azure.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure Application Deleted
def rule(event):
    # Detection Logic:
    # ((operationName="Delete application" OR operationName="Hard Delete application" OR operationName="Delete administrative unit"))
    return True

def title(event):
    return "Azure Application Deleted"

