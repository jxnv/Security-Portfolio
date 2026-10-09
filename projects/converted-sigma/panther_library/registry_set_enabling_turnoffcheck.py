# Title: Scripted Diagnostics Turn Off Check Enabled - Registry
# ID: 7d995e63-ec83-4aa3-89d5-8a17b5c87c86
# Status: test
# Level: medium
# Author: Christopher Peacock @securepeacock, SCYTHE @scythe_io
# Date: 2022-06-15
# Tags: attack.defense-impairment, attack.t1685
# Description: Detects enabling TurnOffCheck which can be used to bypass defense of MSDT Follina vulnerability
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Scripted Diagnostics Turn Off Check Enabled - Registry
def rule(event):
    # Detection Logic:
    # (TargetObject="*\\Policies\\Microsoft\\Windows\\ScriptedDiagnostics\\TurnOffCheck" AND Details="DWORD (0x00000001)")
    return True

def title(event):
    return "Scripted Diagnostics Turn Off Check Enabled - Registry"

