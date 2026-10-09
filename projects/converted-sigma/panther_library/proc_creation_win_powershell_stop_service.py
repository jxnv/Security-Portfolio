# Title: Stop Windows Service Via PowerShell Stop-Service
# ID: c49c5062-0966-4170-9efd-9968c913a6cf
# Status: test
# Level: low
# Author: Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-03-05
# Tags: attack.impact, attack.t1489
# Description: Detects the stopping of a Windows service via the PowerShell Cmdlet "Stop-Service"
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Stop Windows Service Via PowerShell Stop-Service
def rule(event):
    # Detection Logic:
    # ((CommandLine="*Stop-Service *") AND (((OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll")) OR ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe"))))
    return True

def title(event):
    return "Stop Windows Service Via PowerShell Stop-Service"

