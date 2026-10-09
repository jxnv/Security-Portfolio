// Title: Invoke-Obfuscation Via Use MSHTA - PowerShell Module
// ID: 07ad2ea8-6a55-4ac6-bf3e-91b8e59676eb
// Status: test
// Level: high
// Author: Nikita Nazarov, oscd.community
// Date: 2020-10-08
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via use MSHTA in Scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Payload contains "set" and Payload contains "&&" and Payload contains "mshta" and Payload contains "vbscript:createobject" and Payload contains ".run" and Payload contains "(window.close)"))
