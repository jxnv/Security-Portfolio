# Title: PowerShell AppLocker Policy Discovery Via Get-AppLockerPolicy
# ID: f14b1e99-5e53-4598-98dc-6f20ad7b35e0
# Status: experimental
# Level: low
# Author: Tom3306
# Date: 2026-08-19
# Tags: attack.discovery, attack.t1518.001
# Description: Detects AppLocker policy enumeration attempts via PowerShell using the Get-AppLockerPolicy cmdlet and an policy scope of either Effective, LDAP, or Local.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PowerShell AppLocker Policy Discovery Via Get-AppLockerPolicy
def rule(event):
    # Detection Logic:
    # ((CommandLine="*Get-AppLockerPolicy*") AND ((CommandLine="* -Effective*" OR CommandLine="* -Ldap *" OR CommandLine="* -Local*")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll"))))
    return True

def title(event):
    return "PowerShell AppLocker Policy Discovery Via Get-AppLockerPolicy"

