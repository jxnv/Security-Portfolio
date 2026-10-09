// Title: Malicious PowerShell Keywords
// ID: f62176f3-8128-4faa-bf6c-83261322e5eb
// Status: test
// Level: medium
// Author: Sean Metcalf (source), Florian Roth (Nextron Systems)
// Date: 2017-03-05
// Tags: attack.execution, attack.t1059.001
// Description: Detects keywords from well-known PowerShell exploitation frameworks
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "AdjustTokenPrivileges" or ScriptBlockText contains "IMAGE_NT_OPTIONAL_HDR64_MAGIC" or ScriptBlockText contains "Metasploit" or ScriptBlockText contains "Microsoft.Win32.UnsafeNativeMethods" or ScriptBlockText contains "Mimikatz" or ScriptBlockText contains "MiniDumpWriteDump" or ScriptBlockText contains "PAGE_EXECUTE_READ" or ScriptBlockText contains "ReadProcessMemory.Invoke" or ScriptBlockText contains "SE_PRIVILEGE_ENABLED" or ScriptBlockText contains "SECURITY_DELEGATION" or ScriptBlockText contains "TOKEN_ADJUST_PRIVILEGES" or ScriptBlockText contains "TOKEN_ALL_ACCESS" or ScriptBlockText contains "TOKEN_ASSIGN_PRIMARY" or ScriptBlockText contains "TOKEN_DUPLICATE" or ScriptBlockText contains "TOKEN_ELEVATION" or ScriptBlockText contains "TOKEN_IMPERSONATE" or ScriptBlockText contains "TOKEN_INFORMATION_CLASS" or ScriptBlockText contains "TOKEN_PRIVILEGES" or ScriptBlockText contains "TOKEN_QUERY"))
