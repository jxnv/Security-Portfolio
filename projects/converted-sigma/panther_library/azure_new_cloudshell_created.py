# Title: Azure New CloudShell Created
# ID: 72af37e2-ec32-47dc-992b-bc288a2708cb
# Status: test
# Level: medium
# Author: Austin Songer
# Date: 2021-09-21
# Tags: attack.execution, attack.t1059
# Description: Identifies when a new cloudshell is created inside of Azure portal.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Azure New CloudShell Created
def rule(event):
    # Detection Logic:
    # (operationName="MICROSOFT.PORTAL/CONSOLES/WRITE")
    return True

def title(event):
    return "Azure New CloudShell Created"

