# Title: Created Files by Microsoft Sync Center
# ID: 409f8a98-4496-4aaa-818a-c931c0a8b832
# Status: test
# Level: medium
# Author: elhoim
# Date: 2022-04-28
# Tags: attack.privilege-escalation, attack.stealth, attack.t1055, attack.t1218, attack.execution
# Description: This rule detects suspicious files created by Microsoft Sync Center (mobsync)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Created Files by Microsoft Sync Center
def rule(event):
    # Detection Logic:
    # ((Image="*\\mobsync.exe") AND ((TargetFilename="*.dll" OR TargetFilename="*.exe")))
    return True

def title(event):
    return "Created Files by Microsoft Sync Center"

