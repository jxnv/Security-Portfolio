# Title: Winrar Compressing Dump Files
# ID: 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc
# Status: test
# Level: medium
# Author: Florian Roth (Nextron Systems)
# Date: 2022-01-04
# Tags: attack.collection, attack.t1560.001
# Description: Detects execution of WinRAR in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Winrar Compressing Dump Files
def rule(event):
    # Detection Logic:
    # (((CommandLine="*.dmp*" OR CommandLine="*.dump*" OR CommandLine="*.hdmp*")) AND (((Image="*\\rar.exe" OR Image="*\\winrar.exe")) OR (Description="Command line RAR")))
    return True

def title(event):
    return "Winrar Compressing Dump Files"

