# Title: PowerShell Script Run in AppData
# ID: ac175779-025a-4f12-98b0-acdaeb77ea85
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
# Date: 2019-01-09
# Tags: attack.execution, attack.t1059.001
# Description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PowerShell Script Run in AppData
def rule(event):
    # Detection Logic:
    # (((CommandLine="*powershell.exe*" OR CommandLine="*\\powershell*" OR CommandLine="*\\pwsh*" OR CommandLine="*pwsh.exe*")) AND ((CommandLine="*/c *" AND CommandLine="*\\AppData\\*") AND (CommandLine="*Local\\*" OR CommandLine="*Roaming\\*")))
    return True

def title(event):
    return "PowerShell Script Run in AppData"

