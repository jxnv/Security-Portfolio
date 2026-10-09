# Title: Potential ReflectDebugger Content Execution Via WerFault.EXE
# ID: fabfb3a7-3ce1-4445-9c7c-3c27f1051cdd
# Status: test
# Level: medium
# Author: X__Junior (Nextron Systems)
# Date: 2023-06-30
# Tags: attack.execution, attack.stealth, attack.t1036
# Description: Detects execution of "WerFault.exe" with the "-pr" commandline flag that is used to run files stored in the ReflectDebugger key which could be used to store the path to the malware in order to masquerade the execution flow
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential ReflectDebugger Content Execution Via WerFault.EXE
def rule(event):
    # Detection Logic:
    # ((CommandLine="* -pr *") AND ((Image="*\\WerFault.exe") OR (OriginalFileName="WerFault.exe")))
    return True

def title(event):
    return "Potential ReflectDebugger Content Execution Via WerFault.EXE"

