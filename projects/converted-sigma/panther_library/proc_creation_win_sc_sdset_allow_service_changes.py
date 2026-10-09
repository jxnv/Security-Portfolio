# Title: Allow Service Access Using Security Descriptor Tampering Via Sc.EXE
# ID: 6c8fbee5-dee8-49bc-851d-c3142d02aa47
# Status: test
# Level: high
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2023-02-28
# Tags: attack.privilege-escalation, attack.persistence, attack.t1543.003
# Description: Detects suspicious DACL modifications to allow access to a service from a suspicious trustee. This can be used to override access restrictions set by previous ACLs.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Allow Service Access Using Security Descriptor Tampering Via Sc.EXE
def rule(event):
    # Detection Logic:
    # ((((Image="*\\sc.exe") OR (OriginalFileName="sc.exe")) AND ((CommandLine="*sdset*" AND CommandLine="*A;*")) AND ((CommandLine="*;IU*" OR CommandLine="*;SU*" OR CommandLine="*;BA*" OR CommandLine="*;SY*" OR CommandLine="*;WD*"))) AND NOT ((ParentImage="C:\\Hexnode\\Hexnode Agent\\Current\\HexnodeAgent.exe")))
    return True

def title(event):
    return "Allow Service Access Using Security Descriptor Tampering Via Sc.EXE"

