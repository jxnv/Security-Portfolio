# Title: Unusual File Deletion by Dns.exe
# ID: 8f0b1fb1-9bd4-4e74-8cdf-a8de4d2adfd0
# Status: test
# Level: high
# Author: Tim Rauch (Nextron Systems), Elastic (idea)
# Date: 2022-09-27
# Tags: attack.persistence, attack.initial-access, attack.t1133
# Description: Detects an unexpected file being deleted by dns.exe which my indicate activity related to remote code execution or other forms of exploitation as seen in CVE-2020-1350 (SigRed)
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Unusual File Deletion by Dns.exe
def rule(event):
    # Detection Logic:
    # ((Image="*\\dns.exe") AND NOT ((TargetFilename="*\\dns.log")))
    return True

def title(event):
    return "Unusual File Deletion by Dns.exe"

