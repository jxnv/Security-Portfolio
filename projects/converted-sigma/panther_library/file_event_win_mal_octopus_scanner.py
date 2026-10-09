# Title: Octopus Scanner Malware
# ID: 805c55d9-31e6-4846-9878-c34c75054fe9
# Status: test
# Level: high
# Author: NVISO
# Date: 2020-06-09
# Tags: attack.initial-access, attack.t1195, attack.t1195.001
# Description: Detects Octopus Scanner Malware.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Octopus Scanner Malware
def rule(event):
    # Detection Logic:
    # ((TargetFilename="*\\AppData\\Local\\Microsoft\\Cache134.dat" OR TargetFilename="*\\AppData\\Local\\Microsoft\\ExplorerSync.db"))
    return True

def title(event):
    return "Octopus Scanner Malware"

