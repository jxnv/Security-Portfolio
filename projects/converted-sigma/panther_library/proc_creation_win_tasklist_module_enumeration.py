# Title: Loaded Module Enumeration Via Tasklist.EXE
# ID: 34275eb8-fa19-436b-b959-3d9ecd53fa1f
# Status: test
# Level: medium
# Author: Swachchhanda Shrawan Poudel
# Date: 2024-02-12
# Tags: attack.t1003, attack.credential-access
# Description: Detects the enumeration of a specific DLL or EXE being used by a binary via "tasklist.exe".
# This is often used by attackers in order to find the specific process identifier (PID) that is using the DLL in question.
# In order to dump the process memory or perform other nefarious actions.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Loaded Module Enumeration Via Tasklist.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*-m*" OR CommandLine="*/m*")) AND ((Image="*\\tasklist.exe") OR (OriginalFileName="tasklist.exe")) AND (CommandLine="*rdpcorets.dll*"))
    return True

def title(event):
    return "Loaded Module Enumeration Via Tasklist.EXE"

