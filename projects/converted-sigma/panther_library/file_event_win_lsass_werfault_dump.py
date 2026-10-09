# Title: WerFault LSASS Process Memory Dump
# ID: c3e76af5-4ce0-4a14-9c9a-25ceb8fda182
# Status: test
# Level: high
# Author: Florian Roth (Nextron Systems)
# Date: 2022-06-27
# Tags: attack.credential-access, attack.t1003.001
# Description: Detects WerFault creating a dump file with a name that indicates that the dump file could be an LSASS process memory, which contains user credentials
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: WerFault LSASS Process Memory Dump
def rule(event):
    # Detection Logic:
    # (Image="C:\\WINDOWS\\system32\\WerFault.exe" AND (TargetFilename="*\\lsass*" OR TargetFilename="*lsass.exe*"))
    return True

def title(event):
    return "WerFault LSASS Process Memory Dump"

