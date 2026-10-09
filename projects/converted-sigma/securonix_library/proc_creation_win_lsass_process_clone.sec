// Title: Potential Credential Dumping Via LSASS Process Clone
// ID: c8da0dfd-4ed0-4b68-962d-13c9c884384e
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems), Samir Bousseaden
// Date: 2021-11-27
// Tags: attack.credential-access, attack.t1003, attack.t1003.001
// Description: Detects a suspicious LSASS process process clone that could be a sign of credential dumping activity
// Converted by: Sigma Universal SIEM/EDR CLI

(ParentImage="*\\Windows\\System32\\lsass.exe" AND Image="*\\Windows\\System32\\lsass.exe")
