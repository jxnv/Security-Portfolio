// Title: Registry Hide Function from User
// ID: 5a93eb65-dffa-4543-b761-94aa60098fb6
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-03-18
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects registry modifications that hide internal tools or functions from the user (malware like Agent Tesla, Hermetic Wiper uses this technique)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowInfoTip" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowCompColor") and Details = "DWORD (0x00000000)") or ((TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideClock" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCAHealth" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCANetwork" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCAPower" or TargetObject endswith "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\HideSCAVolume") and Details = "DWORD (0x00000001)"))
