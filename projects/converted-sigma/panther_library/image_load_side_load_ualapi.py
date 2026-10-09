# Title: Fax Service DLL Search Order Hijack
# ID: 828af599-4c53-4ed2-ba4a-a9f835c434ea
# Status: test
# Level: high
# Author: NVISO
# Date: 2020-05-04
# Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
# Description: The Fax service attempts to load ualapi.dll, which is non-existent. An attacker can then (side)load their own malicious DLL using this service.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Fax Service DLL Search Order Hijack
def rule(event):
    # Detection Logic:
    # ((Image="*\\fxssvc.exe" AND ImageLoaded="*ualapi.dll") AND NOT ((ImageLoaded="C:\\Windows\\WinSxS\\*")))
    return True

def title(event):
    return "Fax Service DLL Search Order Hijack"

