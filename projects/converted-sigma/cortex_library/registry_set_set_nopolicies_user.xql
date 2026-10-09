// Title: Registry Explorer Policy Modification
// ID: 1c3121ed-041b-4d97-a075-07f54f20fb4a
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-03-18
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects registry modifications that disable internal tools or functions in explorer (malware like Agent Tesla uses this technique)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoLogOff" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDesktop" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoRun" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFind" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoControlPanel" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoFileMenu" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoClose" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoSetTaskbar" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoPropertiesMyDocuments" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoTrayContextMenu") and Details = "DWORD (0x00000001)")
