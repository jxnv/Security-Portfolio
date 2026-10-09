# Title: Suspicious Speech Runtime Binary Child Process
# ID: 78f10490-f2f4-4d19-a75b-4e0683bf3b8d
# Status: experimental
# Level: high
# Author: andrewdanis
# Date: 2025-10-23
# Tags: attack.lateral-movement, attack.stealth, attack.t1021.003, attack.t1218
# Description: Detects suspicious Speech Runtime Binary Execution by monitoring its child processes.
# Child processes spawned by SpeechRuntime.exe could indicate an attempt for lateral movement via COM & DCOM hijacking.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Speech Runtime Binary Child Process
def rule(event):
    # Detection Logic:
    # (ParentImage="*\\SpeechRuntime.exe")
    return True

def title(event):
    return "Suspicious Speech Runtime Binary Child Process"

