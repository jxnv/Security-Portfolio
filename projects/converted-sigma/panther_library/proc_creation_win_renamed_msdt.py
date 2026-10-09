# Title: Renamed Msdt.EXE Execution
# ID: bd1c6866-65fc-44b2-be51-5588fcff82b9
# Status: test
# Level: high
# Author: pH-T (Nextron Systems)
# Date: 2022-06-03
# Tags: attack.stealth, attack.t1036.003
# Description: Detects the execution of a renamed "Msdt.exe" binary
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Renamed Msdt.EXE Execution
def rule(event):
    # Detection Logic:
    # ((OriginalFileName="msdt.exe") AND NOT ((Image="*\\msdt.exe")))
    return True

def title(event):
    return "Renamed Msdt.EXE Execution"

