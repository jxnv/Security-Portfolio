# Title: Shadow Copies Deletion Using Operating Systems Utilities
# ID: c947b146-0abc-4c87-9c64-b17e9d7274a2
# Status: stable
# Level: high
# Author: Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades)
# Date: 2019-10-22
# Tags: attack.impact, attack.stealth, attack.t1070, attack.t1490
# Description: Shadow Copies deletion using operating systems utilities
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Shadow Copies Deletion Using Operating Systems Utilities
def rule(event):
    # Detection Logic:
    # ((((CommandLine="*shadow*" AND CommandLine="*delete*")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wmic.exe" OR Image="*\\vssadmin.exe" OR Image="*\\diskshadow.exe")) OR ((OriginalFileName="PowerShell.EXE" OR OriginalFileName="pwsh.dll" OR OriginalFileName="wmic.exe" OR OriginalFileName="VSSADMIN.EXE" OR OriginalFileName="diskshadow.exe")))) OR (((CommandLine="*delete*" AND CommandLine="*catalog*" AND CommandLine="*quiet*")) AND ((Image="*\\wbadmin.exe") OR (OriginalFileName="WBADMIN.EXE"))) OR (((CommandLine="*resize*" AND CommandLine="*shadowstorage*") AND (CommandLine="*unbounded*" OR CommandLine="*/MaxSize=*")) AND ((Image="*\\vssadmin.exe") OR (OriginalFileName="VSSADMIN.EXE"))))
    return True

def title(event):
    return "Shadow Copies Deletion Using Operating Systems Utilities"

