# Title: Rundll32 UNC Path Execution
# ID: 5cdb711b-5740-4fb2-ba88-f7945027afac
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-10
# Tags: attack.execution, attack.lateral-movement, attack.stealth, attack.t1021.002, attack.t1218.011
# Description: Detects rundll32 execution where the DLL is located on a remote location (share).
# Threat actors can abuse the rundll32.exe binary to execute remote DLLs from a UNC pathh.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Rundll32 UNC Path Execution
def rule(event):
    # Detection Logic:
    # ((((CommandLine="* \\\\\\\\*" OR CommandLine="* '\\\\\\\\*" OR CommandLine="* \"\\\\\\\\*")) AND ((Image="*\\rundll32.exe") OR (OriginalFileName="RUNDLL32.EXE") OR (CommandLine="*rundll32*"))) AND NOT ((CommandLine="*\\\\\\\\.\\\\pipe*")))
    return True

def title(event):
    return "Rundll32 UNC Path Execution"

