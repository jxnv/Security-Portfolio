// Title: Invoke-Obfuscation STDIN+ Launcher - System
// ID: 72862bf2-0eb1-11eb-adc1-0242ac120002
// Status: test
// Level: high
// Author: Jonathan Cheong, oscd.community
// Date: 2020-10-15
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated use of stdin to execute PowerShell
// Converted by: Sigma Universal SIEM/EDR CLI

((Provider_Name == "Service Control Manager" AND EventID == "7045" AND (ImagePath contains "cmd" AND ImagePath contains "powershell") AND (ImagePath contains "/c" OR ImagePath contains "/r")) AND ((ImagePath contains "noexit") OR ((ImagePath contains "input" AND ImagePath contains "$"))))
