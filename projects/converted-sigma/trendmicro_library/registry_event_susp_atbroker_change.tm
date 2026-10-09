// Title: Atbroker Registry Change
// ID: 9577edbb-851f-4243-8c91-1d5b50c1a39b
// Status: test
// Level: medium
// Author: Mateusz Wydra, oscd.community
// Date: 2020-10-13
// Tags: attack.privilege-escalation, attack.stealth, attack.t1218, attack.persistence, attack.t1547
// Description: Detects creation/modification of Assistive Technology applications and persistence with usage of 'at'
// Converted by: Sigma Universal SIEM/EDR CLI

(((TargetObject: "*Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs*" OR TargetObject: "*Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Configuration*")) AND NOT (((Image: "C:\\Windows\\system32\\atbroker.exe" AND TargetObject: "*\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Configuration*" AND Details: "(Empty)") OR (Image="C:\\Windows\\Installer\\MSI*" AND TargetObject: "*Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs*"))))
