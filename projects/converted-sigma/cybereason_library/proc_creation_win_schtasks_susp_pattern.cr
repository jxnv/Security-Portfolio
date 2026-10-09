// Title: Suspicious Command Patterns In Scheduled Task Creation
// ID: f2c64357-b1d2-41b7-849f-34d2682c0fad
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-02-23
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
// Description: Detects scheduled task creation using "schtasks" that contain potentially suspicious or uncommon commands
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\schtasks.exe" AND CommandLine contains "/Create ") AND ((((CommandLine contains "/sc minute " OR CommandLine contains "/ru system ")) AND ((CommandLine contains "cmd /c" OR CommandLine contains "cmd /k" OR CommandLine contains "cmd /r" OR CommandLine contains "cmd.exe /c " OR CommandLine contains "cmd.exe /k " OR CommandLine contains "cmd.exe /r "))) OR ((CommandLine contains " -decode " OR CommandLine contains " -enc " OR CommandLine contains " -w hidden " OR CommandLine contains " bypass " OR CommandLine contains " IEX" OR CommandLine contains ".DownloadData" OR CommandLine contains ".DownloadFile" OR CommandLine contains ".DownloadString" OR CommandLine contains "/c start /min " OR CommandLine contains "FromBase64String" OR CommandLine contains "mshta http" OR CommandLine contains "mshta.exe http")) OR (((CommandLine contains ":\\ProgramData\\" OR CommandLine contains ":\\Temp\\" OR CommandLine contains ":\\Tmp\\" OR CommandLine contains ":\\Users\\Public\\" OR CommandLine contains ":\\Windows\\Temp\\" OR CommandLine contains "\\AppData\\" OR CommandLine contains "%AppData%" OR CommandLine contains "%Temp%" OR CommandLine contains "%tmp%")) AND ((CommandLine contains "cscript" OR CommandLine contains "curl" OR CommandLine contains "wscript")))))
