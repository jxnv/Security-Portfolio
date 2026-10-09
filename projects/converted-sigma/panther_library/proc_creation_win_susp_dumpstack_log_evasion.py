# Title: DumpStack.log Defender Evasion
# ID: 4f647cfa-b598-4e12-ad69-c68dd16caef8
# Status: test
# Level: critical
# Author: Florian Roth (Nextron Systems)
# Date: 2022-01-06
# Tags: attack.defense-impairment
# Description: Detects the use of the filename DumpStack.log to evade Microsoft Defender
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DumpStack.log Defender Evasion
def rule(event):
    # Detection Logic:
    # ((Image="*\\DumpStack.log") OR (CommandLine="* -o DumpStack.log*"))
    return True

def title(event):
    return "DumpStack.log Defender Evasion"

