// Title: Schtasks From Suspicious Folders
// ID: 8a8379b8-780b-4dbf-b1e9-31c8d112fefb
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-04-15
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
// Description: Detects scheduled task creations that have suspicious action command and folder combinations
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "C:\\ProgramData\\" OR CommandLine contains "%ProgramData%")) AND ((CommandLine contains "powershell" OR CommandLine contains "pwsh" OR CommandLine contains "cmd /c " OR CommandLine contains "cmd /k " OR CommandLine contains "cmd /r " OR CommandLine contains "cmd.exe /c " OR CommandLine contains "cmd.exe /k " OR CommandLine contains "cmd.exe /r ")) AND (CommandLine contains " /create ") AND ((Image="*\\schtasks.exe") OR (OriginalFileName == "schtasks.exe")))
