// Title: Invoke-Obfuscation Via Stdin - System
// ID: 487c7524-f892-4054-b263-8a0ace63fc25
// Status: test
// Level: high
// Author: Nikita Nazarov, oscd.community
// Date: 2020-10-12
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via Stdin in Scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Provider_Name = "Service Control Manager" and EventID = 7045 and (ImagePath contains "set" and ImagePath contains "&&") and (ImagePath contains "environment" or ImagePath contains "invoke" or ImagePath contains "input"))
