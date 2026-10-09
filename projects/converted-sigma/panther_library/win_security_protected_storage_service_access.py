# Title: Protected Storage Service Access
# ID: 45545954-4016-43c6-855e-eae8f1c369dc
# Status: test
# Level: high
# Author: Roberto Rodriguez @Cyb3rWard0g
# Date: 2019-08-10
# Tags: attack.lateral-movement, attack.t1021.002
# Description: Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Protected Storage Service Access
def rule(event):
    # Detection Logic:
    # (EventID="5145" AND ShareName="*IPC*" AND RelativeTargetName="protected_storage")
    return True

def title(event):
    return "Protected Storage Service Access"

