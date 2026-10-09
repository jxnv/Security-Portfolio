# Title: Potential Ransomware Activity Using LegalNotice Message
# ID: 8b9606c9-28be-4a38-b146-0e313cc232c1
# Status: test
# Level: high
# Author: frack113
# Date: 2022-12-11
# Tags: attack.impact, attack.t1491.001
# Description: Detect changes to the "LegalNoticeCaption" or "LegalNoticeText" registry values where the message set contains keywords often used in ransomware ransom messages
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Potential Ransomware Activity Using LegalNotice Message
def rule(event):
    # Detection Logic:
    # ((TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption*" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText*") AND (Details="*encrypted*" OR Details="*Unlock-Password*" OR Details="*paying*"))
    return True

def title(event):
    return "Potential Ransomware Activity Using LegalNotice Message"

