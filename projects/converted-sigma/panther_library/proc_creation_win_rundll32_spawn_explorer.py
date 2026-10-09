# Title: RunDLL32 Spawning Explorer
# ID: caa06de8-fdef-4c91-826a-7f9e163eef4b
# Status: test
# Level: high
# Author: elhoim, CD_ROM_
# Date: 2022-04-27
# Tags: attack.stealth, attack.t1218.011
# Description: Detects RunDLL32.exe spawning explorer.exe as child, which is very uncommon, often observes Gamarue spawning the explorer.exe process in an unusual way
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: RunDLL32 Spawning Explorer
def rule(event):
    # Detection Logic:
    # ((ParentImage="*\\rundll32.exe" AND Image="*\\explorer.exe") AND NOT ((ParentCommandLine="*\\shell32.dll,Control_RunDLL*")))
    return True

def title(event):
    return "RunDLL32 Spawning Explorer"

