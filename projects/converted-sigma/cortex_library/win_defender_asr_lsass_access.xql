// Title: LSASS Access Detected via Attack Surface Reduction
// ID: a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98
// Status: test
// Level: high
// Author: Markus Neis
// Date: 2018-08-26
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects Access to LSASS Process
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 1121 and Path endswith "\\lsass.exe") and not ((((ProcessName startswith "C:\\Windows\\System32\\DriverStore\\" or ProcessName startswith "C:\\WINDOWS\\Installer\\" or ProcessName startswith "C:\\Program Files\\" or ProcessName startswith "C:\\Program Files (x86)\\")) or ((ProcessName = "C:\\Windows\\System32\\atiesrxx.exe" or ProcessName = "C:\\Windows\\System32\\CompatTelRunner.exe" or ProcessName = "C:\\Windows\\System32\\msiexec.exe" or ProcessName = "C:\\Windows\\System32\\nvwmi64.exe" or ProcessName = "C:\\Windows\\System32\\svchost.exe" or ProcessName = "C:\\Windows\\System32\\Taskmgr.exe" or ProcessName = "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" or ProcessName = "C:\\Windows\\SysWOW64\\msiexec.exe")) or (ProcessName startswith "C:\\Windows\\Temp\\asgard2-agent\\" and (ProcessName endswith "\\thor64.exe" or ProcessName endswith "\\thor.exe")))))
