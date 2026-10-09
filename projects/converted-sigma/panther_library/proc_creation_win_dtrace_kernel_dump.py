# Title: Suspicious Kernel Dump Using Dtrace
# ID: 7124aebe-4cd7-4ccb-8df0-6d6b93c96795
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2021-12-28
# Tags: attack.discovery, attack.t1082
# Description: Detects suspicious way to dump the kernel on Windows systems using dtrace.exe, which is available on Windows systems since Windows 10 19H1
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Suspicious Kernel Dump Using Dtrace
def rule(event):
    # Detection Logic:
    # (((CommandLine="*syscall:::return*" AND CommandLine="*lkd(*")) OR (Image="*\\dtrace.exe" AND CommandLine="*lkd(0)*"))
    return True

def title(event):
    return "Suspicious Kernel Dump Using Dtrace"

