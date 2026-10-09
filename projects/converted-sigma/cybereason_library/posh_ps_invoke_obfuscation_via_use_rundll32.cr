// Title: Invoke-Obfuscation Via Use Rundll32 - PowerShell
// ID: a5a30a6e-75ca-4233-8b8c-42e0f2037d3b
// Status: test
// Level: high
// Author: Nikita Nazarov, oscd.community
// Date: 2019-10-08
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via use Rundll32 in Scripts
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "&&" AND ScriptBlockText contains "rundll32" AND ScriptBlockText contains "shell32.dll" AND ScriptBlockText contains "shellexec_rundll") AND (ScriptBlockText contains "value" OR ScriptBlockText contains "invoke" OR ScriptBlockText contains "comspec" OR ScriptBlockText contains "iex"))
