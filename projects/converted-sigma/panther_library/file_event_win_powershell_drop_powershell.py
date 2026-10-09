# Title: PowerShell Script Dropped Via PowerShell.EXE
# ID: 576426ad-0131-4001-ae01-be175da0c108
# Status: test
# Level: low
# Author: frack113
# Date: 2023-05-09
# Tags: attack.persistence
# Description: Detects PowerShell creating a PowerShell file (.ps1). While often times this behavior is benign, sometimes it can be a sign of a dropper script trying to achieve persistence.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PowerShell Script Dropped Via PowerShell.EXE
def rule(event):
    # Detection Logic:
    # (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND TargetFilename="*.ps1") AND NOT (((TargetFilename="C:\\Users\\*" AND TargetFilename="*\\AppData\\Local\\Temp\\*") OR (TargetFilename="*__PSScriptPolicyTest_*") OR (TargetFilename="C:\\Windows\\Temp\\*"))))
    return True

def title(event):
    return "PowerShell Script Dropped Via PowerShell.EXE"

