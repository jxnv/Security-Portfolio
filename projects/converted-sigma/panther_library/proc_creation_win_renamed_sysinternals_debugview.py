# Title: Renamed SysInternals DebugView Execution
# ID: cd764533-2e07-40d6-a718-cfeec7f2da7f
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2020-05-28
# Tags: attack.resource-development, attack.t1588.002
# Description: Detects suspicious renamed SysInternals DebugView execution
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Renamed SysInternals DebugView Execution
def rule(event):
    # Detection Logic:
    # ((Product="Sysinternals DebugView") AND NOT ((OriginalFileName="Dbgview.exe" AND Image="*\\Dbgview.exe")))
    return True

def title(event):
    return "Renamed SysInternals DebugView Execution"

