-- Title: Potential WinAPI Calls Via PowerShell Scripts
-- ID: 03d83090-8cba-44a0-b02f-0b756a050306
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Nikita Nazarov, oscd.community
-- Date: 2020-10-06
-- Tags: attack.execution, attack.t1059.001, attack.t1106, attack.stealth, attack.t1620
-- Description: Detects usage of WinAPI functions in PowerShell scripts.
-- It may indicate attempts to perform actions such as process injection, token stealing, or other malicious activities that leverage Windows API calls.
-- These techniques are commonly used to evade traditional file-based detections by loading and executing code directly in memory.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ScriptBlockText ILIKE '%OpenProcessToken%' AND ScriptBlockText ILIKE '%DuplicateTokenEx%' AND ScriptBlockText ILIKE '%CloseHandle%')) OR ((ScriptBlockText ILIKE '%VirtualAlloc%' AND ScriptBlockText ILIKE '%OpenProcess%' AND ScriptBlockText ILIKE '%WriteProcessMemory%' AND ScriptBlockText ILIKE '%CreateRemoteThread%')) OR ((ScriptBlockText ILIKE '%VirtualAlloc%' AND ScriptBlockText ILIKE '%GetDelegateForFunctionPointer%' AND ScriptBlockText ILIKE '%Marshal.Copy%')) OR ((ScriptBlockText ILIKE '%WriteProcessMemory%' AND ScriptBlockText ILIKE '%VirtualAlloc%' AND ScriptBlockText ILIKE '%ReadProcessMemory%' AND ScriptBlockText ILIKE '%VirtualFree%')) OR ((ScriptBlockText ILIKE '%OpenProcessToken%' AND ScriptBlockText ILIKE '%LookupPrivilegeValue%' AND ScriptBlockText ILIKE '%AdjustTokenPrivileges%')))
