# Title: Okta Admin Role Assigned to an User or Group
# ID: 413d4a81-6c98-4479-9863-014785fd579c
# Status: test
# Level: medium
# Author: Austin Songer @austinsonger
# Date: 2021-09-12
# Tags: attack.privilege-escalation, attack.persistence, attack.t1098.003
# Description: Detects when an the Administrator role is assigned to an user or group.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Okta Admin Role Assigned to an User or Group
def rule(event):
    # Detection Logic:
    # ((eventType="group.privilege.grant" OR eventType="user.account.privilege.grant"))
    return True

def title(event):
    return "Okta Admin Role Assigned to an User or Group"

