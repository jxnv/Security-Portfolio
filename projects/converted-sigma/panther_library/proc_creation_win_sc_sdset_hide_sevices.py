# Title: Service DACL Abuse To Hide Services Via Sc.EXE
# ID: a537cfc3-4297-4789-92b5-345bfd845ad0
# Status: test
# Level: high
# Author: Andreas Hunkeler (@Karneades)
# Date: 2021-12-20
# Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.011
# Description: Detects usage of the "sc.exe" utility adding a new service with special permission seen used by threat actors which makes the service hidden and unremovable.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Service DACL Abuse To Hide Services Via Sc.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*sdset*" AND CommandLine="*DCLCWPDTSD*")) AND ((Image="*\\sc.exe") OR (OriginalFileName="sc.exe")))
    return True

def title(event):
    return "Service DACL Abuse To Hide Services Via Sc.EXE"

