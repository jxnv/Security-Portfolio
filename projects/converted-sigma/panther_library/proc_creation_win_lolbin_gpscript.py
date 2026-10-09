# Title: Gpscript Execution
# ID: 1e59c230-6670-45bf-83b0-98903780607e
# Status: test
# Level: medium
# Author: frack113
# Date: 2022-05-16
# Tags: attack.stealth, attack.t1218
# Description: Detects the execution of the LOLBIN gpscript, which executes logon or startup scripts configured in Group Policy
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Gpscript Execution
def rule(event):
    # Detection Logic:
    # ((((CommandLine="* /logon*" OR CommandLine="* /startup*")) AND ((Image="*\\gpscript.exe") OR (OriginalFileName="GPSCRIPT.EXE"))) AND NOT ((ParentCommandLine="C:\\windows\\system32\\svchost.exe -k netsvcs -p -s gpsvc")))
    return True

def title(event):
    return "Gpscript Execution"

