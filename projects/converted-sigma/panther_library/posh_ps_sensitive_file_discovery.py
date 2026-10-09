# Title: Powershell Sensitive File Discovery
# ID: 7d416556-6502-45b2-9bad-9d2f05f38997
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-09-16
# Tags: attack.discovery, attack.t1083
# Description: Detect adversaries enumerate sensitive files
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Powershell Sensitive File Discovery
def rule(event):
    # Detection Logic:
    # (((ScriptBlockText="*ls*" OR ScriptBlockText="*get-childitem*" OR ScriptBlockText="*gci*")) AND ((ScriptBlockText="*.pass*" OR ScriptBlockText="*.kdbx*" OR ScriptBlockText="*.kdb*")) AND (ScriptBlockText="*-recurse*"))
    return True

def title(event):
    return "Powershell Sensitive File Discovery"

