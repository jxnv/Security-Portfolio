# Title: Potential Encoded PowerShell Patterns In CommandLine
# ID: cdf05894-89e7-4ead-b2b0-0a5f97a90f2f
# Status: test
# Level: low
# Author: Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton
# Date: 2020-10-11
# Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
# Description: Detects specific combinations of encoding methods in PowerShell via the commandline
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Encoded PowerShell Patterns In CommandLine
def rule(event):
    # Detection Logic:
    # ((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll"))) AND ((((CommandLine="*ToInt*" OR CommandLine="*ToDecimal*" OR CommandLine="*ToByte*" OR CommandLine="*ToUint*" OR CommandLine="*ToSingle*" OR CommandLine="*ToSByte*")) AND ((CommandLine="*ToChar*" OR CommandLine="*ToString*" OR CommandLine="*String*"))) OR (((CommandLine="*char*" AND CommandLine="*join*")) OR ((CommandLine="*split*" AND CommandLine="*join*")))))
    return True

def title(event):
    return "Potential Encoded PowerShell Patterns In CommandLine"

