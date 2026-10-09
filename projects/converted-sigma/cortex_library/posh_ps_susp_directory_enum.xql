// Title: Powershell Directory Enumeration
// ID: 162e69a7-7981-4344-84a9-0f1c9a217a52
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-03-17
// Tags: attack.discovery, attack.t1083
// Description: Detects technique used by MAZE ransomware to enumerate directories using Powershell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "foreach" and ScriptBlockText contains "Get-ChildItem" and ScriptBlockText contains "-Path " and ScriptBlockText contains "-ErrorAction " and ScriptBlockText contains "SilentlyContinue" and ScriptBlockText contains "Out-File " and ScriptBlockText contains "-append"))
