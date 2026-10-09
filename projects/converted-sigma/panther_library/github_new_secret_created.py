# Title: Github New Secret Created
# ID: f9405037-bc97-4eb7-baba-167dad399b83
# Status: test
# Level: low
# Author: Muhammad Faisal (@faisalusuf)
# Date: 2023-01-20
# Tags: attack.persistence, attack.privilege-escalation, attack.initial-access, attack.stealth, attack.t1078.004
# Description: Detects when a user creates action secret for the organization, environment, codespaces or repository.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Github New Secret Created
def rule(event):
    # Detection Logic:
    # ((action="codespaces.create_an_org_secret" OR action="environment.create_actions_secret" OR action="org.create_actions_secret" OR action="repo.create_actions_secret"))
    return True

def title(event):
    return "Github New Secret Created"

