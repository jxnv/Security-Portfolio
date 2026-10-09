// Title: Invoke-Obfuscation Via Use MSHTA - PowerShell
// ID: e55a5195-4724-480e-a77e-3ebe64bd3759
// Status: test
// Level: high
// Author: Nikita Nazarov, oscd.community
// Date: 2020-10-08
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via use MSHTA in Scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "set" and ScriptBlockText contains "&&" and ScriptBlockText contains "mshta" and ScriptBlockText contains "vbscript:createobject" and ScriptBlockText contains ".run" and ScriptBlockText contains "(window.close)"))
