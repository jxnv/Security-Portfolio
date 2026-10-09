// Title: Suspicious Mshta.EXE Execution Patterns
// ID: e32f92d1-523e-49c3-9374-bdb13b46a3ba
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-07-17
// Tags: attack.execution, attack.t1106
// Description: Detects suspicious mshta process execution patterns
// Converted by: Sigma Universal SIEM/EDR CLI

((((Image="*\\mshta.exe") OR (OriginalFileName == "MSHTA.EXE")) AND ((ParentImage="*\\cmd.exe" OR ParentImage="*\\cscript.exe" OR ParentImage="*\\powershell.exe" OR ParentImage="*\\pwsh.exe" OR ParentImage="*\\regsvr32.exe" OR ParentImage="*\\rundll32.exe" OR ParentImage="*\\wscript.exe") AND (CommandLine contains "\\AppData\\Local\\" OR CommandLine contains "C:\\ProgramData\\" OR CommandLine contains "C:\\Users\\Public\\" OR CommandLine contains "C:\\Windows\\Temp\\"))) OR (((Image="*\\mshta.exe") OR (OriginalFileName == "MSHTA.EXE")) AND NOT ((((Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*")) OR ((CommandLine contains ".htm" OR CommandLine contains ".hta")) OR ((CommandLine="*mshta.exe" OR CommandLine="*mshta"))))))
