# Title: Powershell Keylogging
# ID: 34f90d3c-c297-49e9-b26d-911b05a4866c
# Status: test
# Level: medium
# Author: frack113
# Date: 2021-07-30
# Tags: attack.credential-access, attack.collection, attack.t1056.001
# Description: Adversaries may log user keystrokes to intercept credentials as the user types them.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Powershell Keylogging
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*Get-Keystrokes*") OR ((ScriptBlockText="*Get-ProcAddress user32.dll GetAsyncKeyState*" AND ScriptBlockText="*Get-ProcAddress user32.dll GetForegroundWindow*")))
    return True

def title(event):
    return "Powershell Keylogging"

