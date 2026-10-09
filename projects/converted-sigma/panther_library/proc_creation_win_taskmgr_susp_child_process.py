# Title: New Process Created Via Taskmgr.EXE
# ID: 3d7679bd-0c00-440c-97b0-3f204273e6c7
# Status: test
# Level: low
# Author: Florian Roth (Nextron Systems)
# Date: 2018-03-13
# Tags: attack.stealth, attack.t1036
# Description: Detects the creation of a process via the Windows task manager. This might be an attempt to bypass UAC
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: New Process Created Via Taskmgr.EXE
def rule(event):
    # Detection Logic:
    # ((ParentImage="*\\taskmgr.exe") AND NOT (((Image="*:\\Windows\\System32\\mmc.exe" OR Image="*:\\Windows\\System32\\resmon.exe" OR Image="*:\\Windows\\System32\\Taskmgr.exe"))))
    return True

def title(event):
    return "New Process Created Via Taskmgr.EXE"

