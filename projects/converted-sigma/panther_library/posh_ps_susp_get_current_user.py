# Title: Suspicious PowerShell Get Current User
# ID: 4096a49c-7de4-4da0-a230-c66ccd56ea5a
# Status: test
# Level: low
# Author: frack113
# Date: 2022-04-04
# Tags: attack.discovery, attack.t1033
# Description: Detects the use of PowerShell to identify the current logged user.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious PowerShell Get Current User
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*[System.Environment]::UserName*" OR ScriptBlockText="*$env:UserName*" OR ScriptBlockText="*[System.Security.Principal.WindowsIdentity]::GetCurrent()*"))
    return True

def title(event):
    return "Suspicious PowerShell Get Current User"

