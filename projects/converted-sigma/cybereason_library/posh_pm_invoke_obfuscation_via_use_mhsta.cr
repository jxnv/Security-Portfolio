// Title: Invoke-Obfuscation Via Use MSHTA - PowerShell Module
// ID: 07ad2ea8-6a55-4ac6-bf3e-91b8e59676eb
// Status: test
// Level: high
// Author: Nikita Nazarov, oscd.community
// Date: 2020-10-08
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via use MSHTA in Scripts
// Converted by: Sigma Universal SIEM/EDR CLI

((Payload contains "set" AND Payload contains "&&" AND Payload contains "mshta" AND Payload contains "vbscript:createobject" AND Payload contains ".run" AND Payload contains "(window.close)"))
