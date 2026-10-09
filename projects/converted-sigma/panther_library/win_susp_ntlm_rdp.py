# Title: Potential Remote Desktop Connection to Non-Domain Host
# ID: ce5678bb-b9aa-4fb5-be4b-e57f686256ad
# Status: test
# Level: medium
# Author: James Pemberton
# Date: 2020-05-22
# Tags: attack.command-and-control, attack.t1219.002
# Description: Detects logons using NTLM to hosts that are potentially not part of the domain.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Remote Desktop Connection to Non-Domain Host
def rule(event):
    # Detection Logic:
    # (EventID="8001" AND TargetName="TERMSRV*")
    return True

def title(event):
    return "Potential Remote Desktop Connection to Non-Domain Host"

