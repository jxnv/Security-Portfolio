# Title: DumpMinitool Execution
# ID: dee0a7a3-f200-4112-a99b-952196d81e42
# Status: test
# Level: medium
# Author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
# Date: 2022-04-06
# Tags: attack.stealth, attack.t1036, attack.t1003.001, attack.credential-access
# Description: Detects the use of "DumpMinitool.exe" a tool that allows the dump of process memory via the use of the "MiniDumpWriteDump"
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: DumpMinitool Execution
def rule(event):
    # Detection Logic:
    # (((CommandLine="* Full*" OR CommandLine="* Mini*" OR CommandLine="* WithHeap*")) AND (((Image="*\\DumpMinitool.exe" OR Image="*\\DumpMinitool.x86.exe" OR Image="*\\DumpMinitool.arm64.exe")) OR ((OriginalFileName="DumpMinitool.exe" OR OriginalFileName="DumpMinitool.x86.exe" OR OriginalFileName="DumpMinitool.arm64.exe"))))
    return True

def title(event):
    return "DumpMinitool Execution"

