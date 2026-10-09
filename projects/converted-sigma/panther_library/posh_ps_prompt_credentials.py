# Title: PowerShell Credential Prompt
# ID: ca8b77a9-d499-4095-b793-5d5f330d450e
# Status: test
# Level: high
# Author: John Lambert (idea), Florian Roth (Nextron Systems)
# Date: 2017-04-09
# Tags: attack.credential-access, attack.execution, attack.t1059.001
# Description: Detects PowerShell calling a credential prompt
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PowerShell Credential Prompt
def rule(event):
    # Detection Logic:
    # (ScriptBlockText="*PromptForCredential*")
    return True

def title(event):
    return "PowerShell Credential Prompt"

