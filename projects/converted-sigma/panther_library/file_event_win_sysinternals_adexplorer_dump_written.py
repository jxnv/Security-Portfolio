# Title: ADExplorer Writing Complete AD Snapshot Into .dat File
# ID: 0a1255c5-d732-4b62-ac02-b5152d34fb83
# Status: experimental
# Level: medium
# Author: Arnim Rupp (Nextron Systems), Thomas Patzke
# Date: 2025-07-09
# Tags: attack.discovery, attack.t1087.002, attack.t1069.002, attack.t1482
# Description: Detects the dual use tool ADExplorer writing a complete AD snapshot into a .dat file. This can be used by attackers to extract data for Bloodhound, usernames for password spraying or use the meta data for social engineering. The snapshot doesn't contain password hashes but there have been cases, where administrators put passwords in the comment field.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: ADExplorer Writing Complete AD Snapshot Into .dat File
def rule(event):
    # Detection Logic:
    # ((Image="*\\ADExp.exe" OR Image="*\\ADExplorer.exe" OR Image="*\\ADExplorer64.exe" OR Image="*\\ADExplorer64a.exe") AND TargetFilename="*.dat")
    return True

def title(event):
    return "ADExplorer Writing Complete AD Snapshot Into .dat File"

