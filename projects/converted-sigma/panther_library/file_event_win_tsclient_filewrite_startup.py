# Title: Hijack Legit RDP Session to Move Laterally
# ID: 52753ea4-b3a0-4365-910d-36cff487b789
# Status: test
# Level: high
# Author: Samir Bousseaden
# Date: 2019-02-21
# Tags: attack.command-and-control, attack.t1219.002
# Description: Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Hijack Legit RDP Session to Move Laterally
def rule(event):
    # Detection Logic:
    # (Image="*\\mstsc.exe" AND TargetFilename="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
    return True

def title(event):
    return "Hijack Legit RDP Session to Move Laterally"

