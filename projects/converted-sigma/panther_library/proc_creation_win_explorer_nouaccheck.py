# Title: Explorer NOUACCHECK Flag
# ID: 534f2ef7-e8a2-4433-816d-c91bccde289b
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-02-23
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: Detects suspicious starts of explorer.exe that use the /NOUACCHECK flag that allows to run all sub processes of that newly started explorer.exe without any UAC checks
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Explorer NOUACCHECK Flag
def rule(event):
    # Detection Logic:
    # ((Image="*\\explorer.exe" AND CommandLine="*/NOUACCHECK*") AND NOT (((ParentCommandLine="C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule") OR (ParentImage="C:\\Windows\\System32\\svchost.exe"))))
    return True

def title(event):
    return "Explorer NOUACCHECK Flag"

