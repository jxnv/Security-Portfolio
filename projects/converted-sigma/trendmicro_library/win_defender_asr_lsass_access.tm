// Title: LSASS Access Detected via Attack Surface Reduction
// ID: a0a278fe-2c0e-4de2-ac3c-c68b08a9ba98
// Status: test
// Level: high
// Author: Markus Neis
// Date: 2018-08-26
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects Access to LSASS Process
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID: "1121" AND Path="*\\lsass.exe") AND NOT ((((ProcessName="C:\\Windows\\System32\\DriverStore\\*" OR ProcessName="C:\\WINDOWS\\Installer\\*" OR ProcessName="C:\\Program Files\\*" OR ProcessName="C:\\Program Files (x86)\\*")) OR ((ProcessName: "C:\\Windows\\System32\\atiesrxx.exe" OR ProcessName: "C:\\Windows\\System32\\CompatTelRunner.exe" OR ProcessName: "C:\\Windows\\System32\\msiexec.exe" OR ProcessName: "C:\\Windows\\System32\\nvwmi64.exe" OR ProcessName: "C:\\Windows\\System32\\svchost.exe" OR ProcessName: "C:\\Windows\\System32\\Taskmgr.exe" OR ProcessName: "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" OR ProcessName: "C:\\Windows\\SysWOW64\\msiexec.exe")) OR (ProcessName="C:\\Windows\\Temp\\asgard2-agent\\*" AND (ProcessName="*\\thor64.exe" OR ProcessName="*\\thor.exe")))))
