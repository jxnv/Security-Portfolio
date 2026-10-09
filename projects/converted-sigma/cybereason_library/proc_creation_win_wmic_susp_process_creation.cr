// Title: Suspicious Process Created Via Wmic.EXE
// ID: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2020-10-12
// Tags: attack.execution, attack.t1047
// Description: Detects WMIC executing "process call create" with suspicious calls to processes such as "rundll32", "regsrv32", etc.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains "process " AND CommandLine contains "call " AND CommandLine contains "create ") AND (CommandLine contains "rundll32" OR CommandLine contains "bitsadmin" OR CommandLine contains "regsvr32" OR CommandLine contains "cmd.exe /c " OR CommandLine contains "cmd.exe /k " OR CommandLine contains "cmd.exe /r " OR CommandLine contains "cmd /c " OR CommandLine contains "cmd /k " OR CommandLine contains "cmd /r " OR CommandLine contains "powershell" OR CommandLine contains "pwsh" OR CommandLine contains "certutil" OR CommandLine contains "cscript" OR CommandLine contains "wscript" OR CommandLine contains "mshta" OR CommandLine contains "\\Users\\Public\\" OR CommandLine contains "\\Windows\\Temp\\" OR CommandLine contains "\\AppData\\Local\\" OR CommandLine contains "%temp%" OR CommandLine contains "%tmp%" OR CommandLine contains "%ProgramData%" OR CommandLine contains "%appdata%" OR CommandLine contains "%comspec%" OR CommandLine contains "%localappdata%"))
