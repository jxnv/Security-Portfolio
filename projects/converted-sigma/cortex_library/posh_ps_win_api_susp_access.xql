// Title: Potential WinAPI Calls Via PowerShell Scripts
// ID: 03d83090-8cba-44a0-b02f-0b756a050306
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Nikita Nazarov, oscd.community
// Date: 2020-10-06
// Tags: attack.execution, attack.t1059.001, attack.t1106, attack.stealth, attack.t1620
// Description: Detects usage of WinAPI functions in PowerShell scripts.
// It may indicate attempts to perform actions such as process injection, token stealing, or other malicious activities that leverage Windows API calls.
// These techniques are commonly used to evade traditional file-based detections by loading and executing code directly in memory.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ScriptBlockText contains "OpenProcessToken" and ScriptBlockText contains "DuplicateTokenEx" and ScriptBlockText contains "CloseHandle")) or ((ScriptBlockText contains "VirtualAlloc" and ScriptBlockText contains "OpenProcess" and ScriptBlockText contains "WriteProcessMemory" and ScriptBlockText contains "CreateRemoteThread")) or ((ScriptBlockText contains "VirtualAlloc" and ScriptBlockText contains "GetDelegateForFunctionPointer" and ScriptBlockText contains "Marshal.Copy")) or ((ScriptBlockText contains "WriteProcessMemory" and ScriptBlockText contains "VirtualAlloc" and ScriptBlockText contains "ReadProcessMemory" and ScriptBlockText contains "VirtualFree")) or ((ScriptBlockText contains "OpenProcessToken" and ScriptBlockText contains "LookupPrivilegeValue" and ScriptBlockText contains "AdjustTokenPrivileges")))
