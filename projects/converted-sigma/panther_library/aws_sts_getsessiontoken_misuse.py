# Title: AWS STS GetSessionToken Misuse
# ID: b45ab1d2-712f-4f01-a751-df3826969807
# Status: test
# Level: low
# Author: Austin Songer @austinsonger
# Date: 2021-07-24
# Tags: attack.lateral-movement, attack.privilege-escalation, attack.t1548, attack.t1550, attack.t1550.001
# Description: Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: AWS STS GetSessionToken Misuse
def rule(event):
    # Detection Logic:
    # (eventSource="sts.amazonaws.com" AND eventName="GetSessionToken" AND userIdentity.type="IAMUser")
    return True

def title(event):
    return "AWS STS GetSessionToken Misuse"

