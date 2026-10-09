# Title: DLL Loaded From Suspicious Location Via Cmspt.EXE
# ID: 75e508f7-932d-4ebc-af77-269237a84ce1
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-30
# Tags: attack.stealth, attack.t1218.003
# Description: Detects cmstp loading "dll" or "ocx" files from suspicious locations
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DLL Loaded From Suspicious Location Via Cmspt.EXE
def rule(event):
    # Detection Logic:
    # (Image="*\\cmstp.exe" AND (ImageLoaded="*\\PerfLogs\\*" OR ImageLoaded="*\\ProgramData\\*" OR ImageLoaded="*\\Users\\*" OR ImageLoaded="*\\Windows\\Temp\\*" OR ImageLoaded="*C:\\Temp\\*") AND (ImageLoaded="*.dll" OR ImageLoaded="*.ocx"))
    return True

def title(event):
    return "DLL Loaded From Suspicious Location Via Cmspt.EXE"

