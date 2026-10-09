// Title: PowerShell Set-Acl On Windows Folder - PsScript
// ID: 3bf1d859-3a7e-44cb-8809-a99e066d3478
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-18
// Tags: attack.defense-impairment, attack.t1222
// Description: Detects PowerShell scripts to set the ACL to a file in the Windows folder
// Converted by: Sigma Universal SIEM/EDR CLI

(((ScriptBlockText contains "Set-Acl " AND ScriptBlockText contains "-AclObject ")) AND ((ScriptBlockText contains "-Path \"C:\\Windows" OR ScriptBlockText contains "-Path \"C:/Windows" OR ScriptBlockText contains "-Path 'C:\\Windows" OR ScriptBlockText contains "-Path 'C:/Windows" OR ScriptBlockText contains "-Path C:\\\\Windows" OR ScriptBlockText contains "-Path C:/Windows" OR ScriptBlockText contains "-Path $env:windir" OR ScriptBlockText contains "-Path \"$env:windir" OR ScriptBlockText contains "-Path '$env:windir")) AND ((ScriptBlockText contains "FullControl" OR ScriptBlockText contains "Allow")))
