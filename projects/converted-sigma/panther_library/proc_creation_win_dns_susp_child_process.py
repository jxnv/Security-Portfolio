# Title: Unusual Child Process of dns.exe
# ID: a4e3d776-f12e-42c2-8510-9e6ed1f43ec3
# Status: test
# Level: high
# Author: Tim Rauch, Elastic (idea)
# Date: 2022-09-27
# Tags: attack.persistence, attack.initial-access, attack.t1133
# Description: Detects an unexpected process spawning from dns.exe which may indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Unusual Child Process of dns.exe
def rule(event):
    # Detection Logic:
    # ((ParentImage="*\\dns.exe") AND NOT ((Image="*\\conhost.exe")))
    return True

def title(event):
    return "Unusual Child Process of dns.exe"

