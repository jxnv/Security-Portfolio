# Title: Powershell Inline Execution From A File
# ID: ee218c12-627a-4d27-9e30-d6fb2fe22ed2
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-12-25
# Tags: attack.execution, attack.t1059.001
# Description: Detects inline execution of PowerShell code from a file
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Powershell Inline Execution From A File
def rule(event):
    # Detection Logic:
    # (((CommandLine="*iex *" OR CommandLine="*Invoke-Expression *" OR CommandLine="*Invoke-Command *" OR CommandLine="*icm *")) AND (CommandLine="* -raw*") AND ((CommandLine="*cat *" OR CommandLine="*get-content *" OR CommandLine="*type *")))
    return True

def title(event):
    return "Powershell Inline Execution From A File"

