-- Title: Malicious PowerShell Keywords
-- ID: f62176f3-8128-4faa-bf6c-83261322e5eb
-- Status: test
-- Level: medium
-- Author: Sean Metcalf (source), Florian Roth (Nextron Systems)
-- Date: 2017-03-05
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects keywords from well-known PowerShell exploitation frameworks
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%AdjustTokenPrivileges%' OR ScriptBlockText LIKE '%IMAGE_NT_OPTIONAL_HDR64_MAGIC%' OR ScriptBlockText LIKE '%Metasploit%' OR ScriptBlockText LIKE '%Microsoft.Win32.UnsafeNativeMethods%' OR ScriptBlockText LIKE '%Mimikatz%' OR ScriptBlockText LIKE '%MiniDumpWriteDump%' OR ScriptBlockText LIKE '%PAGE_EXECUTE_READ%' OR ScriptBlockText LIKE '%ReadProcessMemory.Invoke%' OR ScriptBlockText LIKE '%SE_PRIVILEGE_ENABLED%' OR ScriptBlockText LIKE '%SECURITY_DELEGATION%' OR ScriptBlockText LIKE '%TOKEN_ADJUST_PRIVILEGES%' OR ScriptBlockText LIKE '%TOKEN_ALL_ACCESS%' OR ScriptBlockText LIKE '%TOKEN_ASSIGN_PRIMARY%' OR ScriptBlockText LIKE '%TOKEN_DUPLICATE%' OR ScriptBlockText LIKE '%TOKEN_ELEVATION%' OR ScriptBlockText LIKE '%TOKEN_IMPERSONATE%' OR ScriptBlockText LIKE '%TOKEN_INFORMATION_CLASS%' OR ScriptBlockText LIKE '%TOKEN_PRIVILEGES%' OR ScriptBlockText LIKE '%TOKEN_QUERY%'))
