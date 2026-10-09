# Title: Potential LethalHTA Technique Execution
# ID: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
# Status: test
# Level: high
# Author: Markus Neis
# Date: 2018-06-07
# Tags: attack.stealth, attack.t1218.005
# Description: Detects potential LethalHTA technique where the "mshta.exe" is spawned by an "svchost.exe" process
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential LethalHTA Technique Execution
def rule(event):
    # Detection Logic:
    # (ParentImage="*\\svchost.exe" AND Image="*\\mshta.exe")
    return True

def title(event):
    return "Potential LethalHTA Technique Execution"

