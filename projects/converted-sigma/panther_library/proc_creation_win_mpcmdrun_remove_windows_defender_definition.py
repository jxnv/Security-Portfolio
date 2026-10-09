# Title: Windows Defender Definition Files Removed
# ID: 9719a8aa-401c-41af-8108-ced7ec9cd75c
# Status: test
# Level: high
# Author: frack113
# Date: 2021-07-07
# Tags: attack.defense-impairment, attack.t1685
# Description: Adversaries may disable security tools to avoid possible detection of their tools and activities by removing Windows Defender Definition Files
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Windows Defender Definition Files Removed
def rule(event):
    # Detection Logic:
    # (((CommandLine="* -RemoveDefinitions*" AND CommandLine="* -All*")) AND ((Image="*\\MpCmdRun.exe") OR (OriginalFileName="MpCmdRun.exe")))
    return True

def title(event):
    return "Windows Defender Definition Files Removed"

