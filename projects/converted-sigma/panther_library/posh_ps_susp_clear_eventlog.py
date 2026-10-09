# Title: Suspicious Eventlog Clear
# ID: 0f017df3-8f5a-414f-ad6b-24aff1128278
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
# Date: 2022-09-12
# Tags: attack.defense-impairment, attack.t1685.005
# Description: Detects usage of known powershell cmdlets such as "Clear-EventLog" to clear the Windows event logs
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Eventlog Clear
def rule(event):
    # Detection Logic:
    # (((ScriptBlockText="*Clear-EventLog *" OR ScriptBlockText="*Remove-EventLog *" OR ScriptBlockText="*Limit-EventLog *" OR ScriptBlockText="*Clear-WinEvent *")) OR ((ScriptBlockText="*Eventing.Reader.EventLogSession*" AND ScriptBlockText="*ClearLog*")) OR ((ScriptBlockText="*Diagnostics.EventLog*" AND ScriptBlockText="*Clear*")))
    return True

def title(event):
    return "Suspicious Eventlog Clear"

