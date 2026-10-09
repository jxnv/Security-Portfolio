# Title: HackTool - Koh Default Named Pipe
# ID: 0adc67e0-a68f-4ffd-9c43-28905aad5d6a
# Status: test
# Level: critical
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-07-08
# Tags: attack.privilege-escalation, attack.credential-access, attack.stealth, attack.t1528, attack.t1134.001
# Description: Detects creation of default named pipes used by the Koh tool
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - Koh Default Named Pipe
def rule(event):
    # Detection Logic:
    # ((PipeName="*\\imposecost*" OR PipeName="*\\imposingcost*"))
    return True

def title(event):
    return "HackTool - Koh Default Named Pipe"

