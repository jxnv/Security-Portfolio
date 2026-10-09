# Title: HackTool - Mimikatz Kirbi File Creation
# ID: 9e099d99-44c2-42b6-a6d8-54c3545cab29
# Status: test
# Level: critical
# Author: Florian Roth (Nextron Systems), David ANDRE
# Date: 2021-11-08
# Tags: attack.credential-access, attack.t1558
# Description: Detects the creation of files created by mimikatz such as ".kirbi", "mimilsa.log", etc.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - Mimikatz Kirbi File Creation
def rule(event):
    # Detection Logic:
    # ((TargetFilename="*.kirbi" OR TargetFilename="*mimilsa.log"))
    return True

def title(event):
    return "HackTool - Mimikatz Kirbi File Creation"

