// Title: Alternate PowerShell Hosts - PowerShell Module
// ID: 64e8e417-c19a-475a-8d19-98ea705394cc
// Status: test
// Level: medium
// Author: Roberto Rodriguez @Cyb3rWard0g
// Date: 2019-08-11
// Tags: attack.execution, attack.t1059.001
// Description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ContextInfo contains "*") and not (((ContextInfo contains "C:\\Windows\\system32\\dsac.exe") or (ContextInfo contains "ConfigSyncRun.exe") or ((Payload contains "Update-Help" or Payload contains "Failed to update Help for the module")) or ((ContextInfo contains "= powershell" or ContextInfo contains "= C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell" or ContextInfo contains "= C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell" or ContextInfo contains "= C:/Windows/System32/WindowsPowerShell/v1.0/powershell" or ContextInfo contains "= C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell" or ContextInfo contains "= \\\\\\?\\?\\C:Windows\\System32\\WindowsPowerShell\\v1.0\\powershell" or ContextInfo contains "= \\\\\\?\\?\\C:Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell")) or (ContextInfo contains "= C:\\WINDOWS\\System32\\sdiagnhost.exe -Embedding") or (ContextInfo contains "C:\\Windows\\system32\\wsmprovhost.exe -Embedding"))))
