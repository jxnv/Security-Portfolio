# Title: HackTool - PowerTool Execution
# ID: a34f79a3-8e5f-4cc3-b765-de00695452c2
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-11-29
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects the execution of the tool PowerTool which has the ability to kill a process, delete its process file, unload drivers, and delete the driver files
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - PowerTool Execution
def rule(event):
    # Detection Logic:
    # (((Image="*\\PowerTool.exe" OR Image="*\\PowerTool64.exe")) OR (OriginalFileName="PowerTool.exe"))
    return True

def title(event):
    return "HackTool - PowerTool Execution"

