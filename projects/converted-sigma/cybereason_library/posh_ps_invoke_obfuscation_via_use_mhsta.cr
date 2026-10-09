// Title: Invoke-Obfuscation Via Use MSHTA - PowerShell
// ID: e55a5195-4724-480e-a77e-3ebe64bd3759
// Status: test
// Level: high
// Author: Nikita Nazarov, oscd.community
// Date: 2020-10-08
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via use MSHTA in Scripts
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "set" AND ScriptBlockText contains "&&" AND ScriptBlockText contains "mshta" AND ScriptBlockText contains "vbscript:createobject" AND ScriptBlockText contains ".run" AND ScriptBlockText contains "(window.close)"))
