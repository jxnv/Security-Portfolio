# Title: Standard User In High Privileged Group
# ID: 7ac407cc-0f48-4328-aede-de1d2e6fef41
# Status: test
# Level: medium
# Author: frack113
# Date: 2023-01-13
# Tags: attack.credential-access, attack.privilege-escalation
# Description: Detect standard users login that are part of high privileged groups such as the Administrator group
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Standard User In High Privileged Group
def rule(event):
    # Detection Logic:
    # ((EventID="300" AND TargetUserSid="S-1-5-21-*" AND (SidList="*S-1-5-32-544*" OR SidList="*-500}*" OR SidList="*-518}*" OR SidList="*-519}*")) AND NOT (((TargetUserSid="*-500" OR TargetUserSid="*-518" OR TargetUserSid="*-519"))))
    return True

def title(event):
    return "Standard User In High Privileged Group"

