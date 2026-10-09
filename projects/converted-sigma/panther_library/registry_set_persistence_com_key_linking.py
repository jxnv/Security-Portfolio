# Title: Potential COM Object Hijacking Via TreatAs Subkey - Registry
# ID: 9b0f8a61-91b2-464f-aceb-0527e0a45020
# Status: test
# Level: medium
# Author: Kutepov Anton, oscd.community
# Date: 2019-10-23
# Tags: attack.privilege-escalation, attack.persistence, attack.t1546.015
# Description: Detects COM object hijacking via TreatAs subkey
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential COM Object Hijacking Via TreatAs Subkey - Registry
def rule(event):
    # Detection Logic:
    # (((TargetObject="*HKU\\*" AND TargetObject="*Classes\\CLSID\\*" AND TargetObject="*\\TreatAs*")) AND NOT ((Image="C:\\WINDOWS\\system32\\svchost.exe")))
    return True

def title(event):
    return "Potential COM Object Hijacking Via TreatAs Subkey - Registry"

