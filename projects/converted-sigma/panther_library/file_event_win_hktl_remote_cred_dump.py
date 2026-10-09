# Title: HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump
# ID: 6e2a900a-ced9-4e4a-a9c2-13e706f9518a
# Status: test
# Level: high
# Author: SecurityAura
# Date: 2022-11-16
# Tags: attack.credential-access, attack.t1003
# Description: Detects default filenames output from the execution of CrackMapExec and Impacket-secretsdump against an endpoint.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump
def rule(event):
    # Detection Logic:
    # (Image="*\\svchost.exe" AND TargetFilename=regex("\\\\Windows\\\\System32\\\\[a-zA-Z0-9]{8}\\.tmp$"))
    return True

def title(event):
    return "HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump"

