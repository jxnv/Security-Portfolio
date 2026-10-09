// Title: Delete All Scheduled Tasks
// ID: 220457c1-1c9f-4c2e-afe6-9598926222c1
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.impact, attack.t1489
// Description: Detects the usage of schtasks with the delete flag and the asterisk symbol to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*\\schtasks.exe" AND (CommandLine: "* /delete *" AND CommandLine: "*/tn \\**" AND CommandLine: "* /f*"))
