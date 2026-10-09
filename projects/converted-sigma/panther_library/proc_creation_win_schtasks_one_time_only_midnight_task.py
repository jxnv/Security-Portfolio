# Title: Uncommon One Time Only Scheduled Task At 00:00
# ID: 970823b7-273b-460a-8afc-3a6811998529
# Status: test
# Level: high
# Author: pH-T (Nextron Systems)
# Date: 2022-07-15
# Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.t1053.005
# Description: Detects scheduled task creation events that include suspicious actions, and is run once at 00:00
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Uncommon One Time Only Scheduled Task At 00:00
def rule(event):
    # Detection Logic:
    # (((CommandLine="*wscript*" OR CommandLine="*vbscript*" OR CommandLine="*cscript*" OR CommandLine="*wmic *" OR CommandLine="*wmic.exe*" OR CommandLine="*regsvr32.exe*" OR CommandLine="*powershell*" OR CommandLine="*\\AppData\\*")) AND ((Image="*\\schtasks.exe*") OR (OriginalFileName="schtasks.exe")) AND ((CommandLine="*once*" AND CommandLine="*00:00*")))
    return True

def title(event):
    return "Uncommon One Time Only Scheduled Task At 00:00"

