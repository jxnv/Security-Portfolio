# Title: MSDT Execution Via Answer File
# ID: 9c8c7000-3065-44a8-a555-79bcba5d9955
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-06-13
# Tags: attack.stealth, attack.t1218, attack.execution
# Description: Detects execution of "msdt.exe" using an answer file which is simulating the legitimate way of calling msdt via "pcwrun.exe" (For example from the compatibility tab).
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: MSDT Execution Via Answer File
def rule(event):
    # Detection Logic:
    # ((Image="*\\msdt.exe" AND CommandLine="*\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml*" AND CommandLine="* -af *") AND NOT ((ParentImage="*\\pcwrun.exe")))
    return True

def title(event):
    return "MSDT Execution Via Answer File"

