# Title: Use of FSharp Interpreters
# ID: b96b2031-7c17-4473-afe7-a30ce714db29
# Status: test
# Level: medium
# Author: Christopher Peacock @SecurePeacock, SCYTHE @scythe_io
# Date: 2022-06-02
# Tags: attack.execution, attack.t1059
# Description: Detects the execution of FSharp Interpreters "FsiAnyCpu.exe" and "FSi.exe"
# Both can be used for AWL bypass and to execute F# code via scripts or inline.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Use of FSharp Interpreters
def rule(event):
    # Detection Logic:
    # (((Image="*\\fsi.exe" OR Image="*\\fsianycpu.exe")) OR ((OriginalFileName="fsi.exe" OR OriginalFileName="fsianycpu.exe")))
    return True

def title(event):
    return "Use of FSharp Interpreters"

