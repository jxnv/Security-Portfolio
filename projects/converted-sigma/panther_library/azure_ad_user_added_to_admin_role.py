# Title: User Added to an Administrator's Azure AD Role
# ID: ebbeb024-5b1d-4e16-9c0c-917f86c708a7
# Status: test
# Level: medium
# Author: Raphaël CALVET, @MetallicHack
# Date: 2021-10-04
# Tags: attack.initial-access, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1098.003, attack.t1078
# Description: User Added to an Administrator's Azure AD Role
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: User Added to an Administrator's Azure AD Role
def rule(event):
    # Detection Logic:
    # (operationName="Add member to role" AND (properties.targetResources="*Admins*" OR properties.targetResources="*Administrator*"))
    return True

def title(event):
    return "User Added to an Administrator's Azure AD Role"

