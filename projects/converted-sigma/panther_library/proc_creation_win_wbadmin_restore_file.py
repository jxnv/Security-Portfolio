# Title: File Recovery From Backup Via Wbadmin.EXE
# ID: 6fe4aa1e-0531-4510-8be2-782154b73b48
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems), frack113
# Date: 2024-05-10
# Tags: attack.impact, attack.t1490
# Description: Detects the recovery of files from backups via "wbadmin.exe".
# Attackers can restore sensitive files such as NTDS.DIT or Registry Hives from backups in order to potentially extract credentials.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: File Recovery From Backup Via Wbadmin.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="* recovery*" AND CommandLine="*recoveryTarget*" AND CommandLine="*itemtype:File*")) AND ((Image="*\\wbadmin.exe") OR (OriginalFileName="WBADMIN.EXE")))
    return True

def title(event):
    return "File Recovery From Backup Via Wbadmin.EXE"

