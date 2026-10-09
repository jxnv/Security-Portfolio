# Title: HackTool - KrbRelay Execution
# ID: e96253b8-6b3b-4f90-9e59-3b24b99cf9b4
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-04-27
# Tags: attack.credential-access, attack.t1558.003
# Description: Detects the use of KrbRelay, a Kerberos relaying tool
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - KrbRelay Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="* -spn *" AND CommandLine="* -clsid *" AND CommandLine="* -rbcd *")) OR ((CommandLine="*shadowcred*" AND CommandLine="*clsid*" AND CommandLine="*spn*")) OR ((CommandLine="*spn *" AND CommandLine="*session *" AND CommandLine="*clsid *")) OR ((Image="*\\KrbRelay.exe") OR (OriginalFileName="KrbRelay.exe")))
    return True

def title(event):
    return "HackTool - KrbRelay Execution"

