# Title: PowerShell Core DLL Loaded Via Office Application
# ID: bb2ba6fb-95d4-4a25-89fc-30bb736c021a
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-06-01
# Tags: attack.stealth
# Description: Detects PowerShell core DLL being loaded by an Office Product
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: PowerShell Core DLL Loaded Via Office Application
def rule(event):
    # Detection Logic:
    # ((Image="*\\excel.exe" OR Image="*\\mspub.exe" OR Image="*\\outlook.exe" OR Image="*\\onenote.exe" OR Image="*\\onenoteim.exe" OR Image="*\\powerpnt.exe" OR Image="*\\winword.exe") AND (ImageLoaded="*\\System.Management.Automation.Dll*" OR ImageLoaded="*\\System.Management.Automation.ni.Dll*"))
    return True

def title(event):
    return "PowerShell Core DLL Loaded Via Office Application"

