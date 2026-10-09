# Title: Remote CHM File Download/Execution Via HH.EXE
# ID: f57c58b3-ee69-4ef5-9041-455bf39aaa89
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-09-29
# Tags: attack.stealth, attack.t1218.001
# Description: Detects the usage of "hh.exe" to execute/download remotely hosted ".chm" files.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Remote CHM File Download/Execution Via HH.EXE
def rule(event):
    # Detection Logic:
    # (((CommandLine="*http://*" OR CommandLine="*https://*" OR CommandLine="*\\\\\\\\*")) AND ((OriginalFileName="HH.exe") OR (Image="*\\hh.exe")))
    return True

def title(event):
    return "Remote CHM File Download/Execution Via HH.EXE"

