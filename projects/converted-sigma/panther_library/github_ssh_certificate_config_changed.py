# Title: Github SSH Certificate Configuration Changed
# ID: 2f575940-d85e-4ddc-af13-17dad6f1a0ef
# Status: test
# Level: medium
# Author: Romain Gaillard (@romain-gaillard)
# Date: 2024-07-29
# Tags: attack.initial-access, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1078.004
# Description: Detects when changes are made to the SSH certificate configuration of the organization.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Github SSH Certificate Configuration Changed
def rule(event):
    # Detection Logic:
    # ((action="ssh_certificate_authority.create" OR action="ssh_certificate_requirement.disable"))
    return True

def title(event):
    return "Github SSH Certificate Configuration Changed"

