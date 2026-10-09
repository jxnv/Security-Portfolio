// Title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System
// ID: 14bcba49-a428-42d9-b943-e2ce0f0f7ae6
// Status: test
// Level: high
// Author: Timur Zinniatullin, oscd.community
// Date: 2020-10-13
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via VAR++ LAUNCHER
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Provider_Name = "Service Control Manager" and EventID = 7045 and (ImagePath contains "&&set" and ImagePath contains "cmd" and ImagePath contains "/c" and ImagePath contains "-f") and (ImagePath contains "{0}" or ImagePath contains "{1}" or ImagePath contains "{2}" or ImagePath contains "{3}" or ImagePath contains "{4}" or ImagePath contains "{5}"))
