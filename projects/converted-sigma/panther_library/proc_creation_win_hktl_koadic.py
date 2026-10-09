# Title: HackTool - Koadic Execution
# ID: 5cddf373-ef00-4112-ad72-960ac29bac34
# Status: test
# Level: high
# Author: wagga, Jonhnathan Ribeiro, oscd.community
# Date: 2020-01-12
# Tags: attack.execution, attack.t1059.003, attack.t1059.005, attack.t1059.007
# Description: Detects command line parameters used by Koadic hack tool
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - Koadic Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="*/q*" AND CommandLine="*/c*" AND CommandLine="*chcp*")) AND ((Image="*\\cmd.exe") OR (OriginalFileName="Cmd.Exe")))
    return True

def title(event):
    return "HackTool - Koadic Execution"

