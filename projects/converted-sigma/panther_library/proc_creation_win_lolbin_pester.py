# Title: Execute Code with Pester.bat as Parent
# ID: 18988e1b-9087-4f8a-82fe-0414dce49878
# Status: test
# Level: medium
# Author: frack113, Nasreddine Bencherchali
# Date: 2022-08-20
# Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1216
# Description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Execute Code with Pester.bat as Parent
def rule(event):
    # Detection Logic:
    # (((ParentCommandLine="*{ Invoke-Pester -EnableExit ;*" OR ParentCommandLine="*{ Get-Help \"*")) AND ((ParentImage="*\\powershell.exe" OR ParentImage="*\\pwsh.exe") AND ParentCommandLine="*\\WindowsPowerShell\\Modules\\Pester\\*"))
    return True

def title(event):
    return "Execute Code with Pester.bat as Parent"

