# Title: Potential UAC Bypass Via Sdclt.EXE
# ID: 40f9af16-589d-4984-b78d-8c2aec023197
# Status: test
# Level: medium
# Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
# Date: 2020-05-02
# Tags: attack.privilege-escalation, attack.t1548.002
# Description: A General detection for sdclt being spawned as an elevated process. This could be an indicator of sdclt being used for bypass UAC techniques.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential UAC Bypass Via Sdclt.EXE
def rule(event):
    # Detection Logic:
    # (Image="*sdclt.exe" AND (IntegrityLevel="High" OR IntegrityLevel="S-1-16-12288"))
    return True

def title(event):
    return "Potential UAC Bypass Via Sdclt.EXE"

