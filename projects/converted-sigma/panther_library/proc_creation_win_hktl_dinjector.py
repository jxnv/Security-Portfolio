# Title: HackTool - DInjector PowerShell Cradle Execution
# ID: d78b5d61-187d-44b6-bf02-93486a80de5a
# Status: test
# Level: critical
# Author: Florian Roth (Nextron Systems)
# Date: 2021-12-07
# Tags: attack.privilege-escalation, attack.stealth, attack.t1055
# Description: Detects the use of the Dinject PowerShell cradle based on the specific flags
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - DInjector PowerShell Cradle Execution
def rule(event):
    # Detection Logic:
    # ((CommandLine="* /am51*" AND CommandLine="* /password*"))
    return True

def title(event):
    return "HackTool - DInjector PowerShell Cradle Execution"

