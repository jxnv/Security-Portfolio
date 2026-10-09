// Title: Invoke-Obfuscation COMPRESS OBFUSCATION - System
// ID: 175997c5-803c-4b08-8bb0-70b099f47595
// Status: test
// Level: medium
// Author: Timur Zinniatullin, oscd.community
// Date: 2020-10-18
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Provider_Name = "Service Control Manager" and EventID = 7045 and (ImagePath contains "new-object" and ImagePath contains "text.encoding]::ascii" and ImagePath contains "readtoend") and (ImagePath contains ":system.io.compression.deflatestream" or ImagePath contains "system.io.streamreader"))
