// Title: Invoke-Obfuscation Via Use Rundll32 - PowerShell
// ID: a5a30a6e-75ca-4233-8b8c-42e0f2037d3b
// Status: test
// Level: high
// Author: Nikita Nazarov, oscd.community
// Date: 2019-10-08
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via use Rundll32 in Scripts
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText: "*&&*" AND ScriptBlockText: "*rundll32*" AND ScriptBlockText: "*shell32.dll*" AND ScriptBlockText: "*shellexec_rundll*") AND (ScriptBlockText: "*value*" OR ScriptBlockText: "*invoke*" OR ScriptBlockText: "*comspec*" OR ScriptBlockText: "*iex*"))
