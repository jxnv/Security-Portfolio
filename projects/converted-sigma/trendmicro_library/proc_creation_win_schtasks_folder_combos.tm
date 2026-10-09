// Title: Schtasks From Suspicious Folders
// ID: 8a8379b8-780b-4dbf-b1e9-31c8d112fefb
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-04-15
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
// Description: Detects scheduled task creations that have suspicious action command and folder combinations
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*C:\\ProgramData\\*" OR CommandLine: "*%ProgramData%*")) AND ((CommandLine: "*powershell*" OR CommandLine: "*pwsh*" OR CommandLine: "*cmd /c *" OR CommandLine: "*cmd /k *" OR CommandLine: "*cmd /r *" OR CommandLine: "*cmd.exe /c *" OR CommandLine: "*cmd.exe /k *" OR CommandLine: "*cmd.exe /r *")) AND (CommandLine: "* /create *") AND ((Image="*\\schtasks.exe") OR (OriginalFileName: "schtasks.exe")))
