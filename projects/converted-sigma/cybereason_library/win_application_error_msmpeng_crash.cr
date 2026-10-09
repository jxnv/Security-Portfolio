// Title: Microsoft Malware Protection Engine Crash
// ID: 545a5da6-f103-4919-a519-e9aec1026ee4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2017-05-09
// Tags: attack.stealth, attack.defense-impairment, attack.t1211, attack.t1685
// Description: This rule detects a suspicious crash of the Microsoft Malware Protection Engine
// Converted by: Sigma Universal SIEM/EDR CLI

(Provider_Name == "Application Error" AND EventID == "1000" AND (Data contains "MsMpEng.exe" AND Data contains "mpengine.dll"))
