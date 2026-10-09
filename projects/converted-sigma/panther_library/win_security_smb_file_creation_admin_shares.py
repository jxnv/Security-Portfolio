# Title: SMB Create Remote File Admin Share
# ID: b210394c-ba12-4f89-9117-44a2464b9511
# Status: test
# Level: high
# Author: Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research)
# Date: 2020-08-06
# Tags: attack.lateral-movement, attack.t1021.002
# Description: Look for non-system accounts SMB accessing a file with write (0x2) access mask via administrative share (i.e C$).
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: SMB Create Remote File Admin Share
def rule(event):
    # Detection Logic:
    # ((EventID="5145" AND ShareName="*C$" AND AccessMask="0x2") AND NOT ((SubjectUserName="*$")) AND NOT ((IpAddress="::1")))
    return True

def title(event):
    return "SMB Create Remote File Admin Share"

