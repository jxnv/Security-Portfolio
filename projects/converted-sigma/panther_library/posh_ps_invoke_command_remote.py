# Title: Execute Invoke-command on Remote Host
# ID: 7b836d7f-179c-4ba4-90a7-a7e60afb48e6
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-01-07
# Tags: attack.lateral-movement, attack.t1021.006
# Description: Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Execute Invoke-command on Remote Host
def rule(event):
    # Detection Logic:
    # ((ScriptBlockText="*invoke-command *" AND ScriptBlockText="* -ComputerName *"))
    return True

def title(event):
    return "Execute Invoke-command on Remote Host"

