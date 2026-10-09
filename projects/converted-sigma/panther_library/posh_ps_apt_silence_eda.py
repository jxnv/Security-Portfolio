# Title: Silence.EDA Detection
# ID: 3ceb2083-a27f-449a-be33-14ec1b7cc973
# Status: test
# Level: critical
# Author: Alina Stepchenkova, Group-IB, oscd.community
# Date: 2019-11-01
# Tags: attack.execution, attack.t1059.001, attack.command-and-control, attack.t1071.004, attack.t1572, attack.impact, attack.t1529, attack.g0091, attack.s0363
# Description: Detects Silence EmpireDNSAgent as described in the Group-IP report
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Silence.EDA Detection
def rule(event):
    # Detection Logic:
    # (((ScriptBlockText="*System.Diagnostics.Process*" AND ScriptBlockText="*Stop-Computer*" AND ScriptBlockText="*Restart-Computer*" AND ScriptBlockText="*Exception in execution*" AND ScriptBlockText="*$cmdargs*" AND ScriptBlockText="*Close-Dnscat2Tunnel*")) AND ((ScriptBlockText="*set type=$LookupType`nserver*" AND ScriptBlockText="*$Command | nslookup 2>&1 | Out-String*" AND ScriptBlockText="*New-RandomDNSField*" AND ScriptBlockText="*[Convert]::ToString($SYNOptions, 16)*" AND ScriptBlockText="*$Session.Dead = $True*" AND ScriptBlockText="*$Session[\"Driver\"] -eq*")))
    return True

def title(event):
    return "Silence.EDA Detection"

