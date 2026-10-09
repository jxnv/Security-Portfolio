// Title: Potential Ransomware Activity Using LegalNotice Message
// ID: 8b9606c9-28be-4a38-b146-0e313cc232c1
// Status: test
// Level: high
// Author: frack113
// Date: 2022-12-11
// Tags: attack.impact, attack.t1491.001
// Description: Detect changes to the "LegalNoticeCaption" or "LegalNoticeText" registry values where the message set contains keywords often used in ransomware ransom messages
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption" or TargetObject contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText") and (Details contains "encrypted" or Details contains "Unlock-Password" or Details contains "paying"))
