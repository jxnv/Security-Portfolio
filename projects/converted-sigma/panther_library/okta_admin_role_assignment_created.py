# Title: Okta Admin Role Assignment Created
# ID: 139bdd4b-9cd7-49ba-a2f4-744d0a8f5d8c
# Status: test
# Level: medium
# Author: Nikita Khalimonenkov
# Date: 2023-01-19
# Tags: attack.persistence
# Description: Detects when a new admin role assignment is created. Which could be a sign of privilege escalation or persistence
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta Admin Role Assignment Created
def rule(event):
    # Detection Logic:
    # (eventType="iam.resourceset.bindings.add")
    return True

def title(event):
    return "Okta Admin Role Assignment Created"

