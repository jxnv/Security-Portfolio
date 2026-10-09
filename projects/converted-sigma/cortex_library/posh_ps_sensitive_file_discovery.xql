// Title: Powershell Sensitive File Discovery
// ID: 7d416556-6502-45b2-9bad-9d2f05f38997
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-09-16
// Tags: attack.discovery, attack.t1083
// Description: Detect adversaries enumerate sensitive files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ScriptBlockText contains "ls" or ScriptBlockText contains "get-childitem" or ScriptBlockText contains "gci")) and ((ScriptBlockText contains ".pass" or ScriptBlockText contains ".kdbx" or ScriptBlockText contains ".kdb")) and (ScriptBlockText contains "-recurse"))
