# Title: Permission Misconfiguration Reconnaissance Via Findstr.EXE
# ID: 47e4bab7-c626-47dc-967b-255608c9a920
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems)
# Date: 2022-08-12
# Tags: attack.credential-access, attack.t1552.006
# Description: Detects usage of findstr with the "EVERYONE" or "BUILTIN" keywords.
# This was seen being used in combination with "icacls" and other utilities to spot misconfigured files or folders permissions.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Permission Misconfiguration Reconnaissance Via Findstr.EXE
def rule(event):
    # Detection Logic:
    # ((((CommandLine="*\"Everyone\"*" OR CommandLine="*'Everyone'*" OR CommandLine="*\"BUILTIN\\\\\"*" OR CommandLine="*'BUILTIN\\'*")) AND (((Image="*\\find.exe" OR Image="*\\findstr.exe")) OR ((OriginalFileName="FIND.EXE" OR OriginalFileName="FINDSTR.EXE")))) OR ((CommandLine="*icacls *" AND CommandLine="*findstr *" AND CommandLine="*Everyone*")))
    return True

def title(event):
    return "Permission Misconfiguration Reconnaissance Via Findstr.EXE"

