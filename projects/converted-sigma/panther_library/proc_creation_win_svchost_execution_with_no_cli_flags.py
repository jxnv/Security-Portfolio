# Title: Suspect Svchost Activity
# ID: 16c37b52-b141-42a5-a3ea-bbe098444397
# Status: test
# Level: high
# Author: David Burkett, @signalblur
# Date: 2019-12-28
# Tags: attack.privilege-escalation, attack.stealth, attack.t1055
# Description: It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspect Svchost Activity
def rule(event):
    # Detection Logic:
    # ((CommandLine="*svchost.exe" AND Image="*\\svchost.exe") AND NOT ((((ParentImage="*\\rpcnet.exe" OR ParentImage="*\\rpcnetp.exe")) OR (NOT CommandLine=*))))
    return True

def title(event):
    return "Suspect Svchost Activity"

