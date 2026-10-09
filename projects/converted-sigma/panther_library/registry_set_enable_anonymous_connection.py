# Title: Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback
# ID: 4d431012-2ab5-4db7-a84e-b29809da2172
# Status: test
# Level: medium
# Author: X__Junior (Nextron Systems)
# Date: 2023-11-03
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects enabling of the "AllowAnonymousCallback" registry value, which allows a remote connection between computers that do not have a trust relationship.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\Microsoft\\WBEM\\CIMOM\\AllowAnonymousCallback*" AND Details="DWORD (0x00000001)")
    return True

def title(event):
    return "Enable Remote Connection Between Anonymous Computer - AllowAnonymousCallback"

