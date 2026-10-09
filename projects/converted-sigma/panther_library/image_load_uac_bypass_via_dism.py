# Title: UAC Bypass With Fake DLL
# ID: a5ea83a7-05a5-44c1-be2e-addccbbd8c03
# Status: test
# Level: high
# Author: oscd.community, Dmitry Uchakin
# Date: 2020-10-06
# Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1548.002, attack.t1574.001
# Description: Attempts to load dismcore.dll after dropping it
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: UAC Bypass With Fake DLL
def rule(event):
    # Detection Logic:
    # ((Image="*\\dism.exe" AND ImageLoaded="*\\dismcore.dll") AND NOT ((ImageLoaded="C:\\Windows\\System32\\Dism\\dismcore.dll")))
    return True

def title(event):
    return "UAC Bypass With Fake DLL"

