# Title: HackTool - Covenant PowerShell Launcher
# ID: c260b6db-48ba-4b4a-a76f-2f67644e99d2
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
# Date: 2020-06-04
# Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1564.003
# Description: Detects suspicious command lines used in Covenant luanchers
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - Covenant PowerShell Launcher
def rule(event):
    # Detection Logic:
    # (((CommandLine="*-Sta*" AND CommandLine="*-Nop*" AND CommandLine="*-Window*" AND CommandLine="*Hidden*") AND (CommandLine="*-Command*" OR CommandLine="*-EncodedCommand*")) OR ((CommandLine="*sv o (New-Object IO.MemorySteam);sv d *" OR CommandLine="*mshta file.hta*" OR CommandLine="*GruntHTTP*" OR CommandLine="*-EncodedCommand cwB2ACAAbwAgA*")))
    return True

def title(event):
    return "HackTool - Covenant PowerShell Launcher"

