# Title: HackTool - SharPersist Execution
# ID: 26488ad0-f9fd-4536-876f-52fea846a2e4
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-09-15
# Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053
# Description: Detects the execution of the hacktool SharPersist - used to deploy various different kinds of persistence mechanisms
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - SharPersist Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="* -t schtask -c *" OR CommandLine="* -t startupfolder -c *")) OR ((CommandLine="* -t reg -c *" AND CommandLine="* -m add*")) OR ((CommandLine="* -t service -c *" AND CommandLine="* -m add*")) OR ((CommandLine="* -t schtask -c *" AND CommandLine="* -m add*")) OR ((Image="*\\SharPersist.exe") OR (Product="SharPersist")))
    return True

def title(event):
    return "HackTool - SharPersist Execution"

