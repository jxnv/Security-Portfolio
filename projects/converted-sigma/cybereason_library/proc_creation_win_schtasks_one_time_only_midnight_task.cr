// Title: Uncommon One Time Only Scheduled Task At 00:00
// ID: 970823b7-273b-460a-8afc-3a6811998529
// Status: test
// Level: high
// Author: pH-T (Nextron Systems)
// Date: 2022-07-15
// Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.t1053.005
// Description: Detects scheduled task creation events that include suspicious actions, and is run once at 00:00
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "wscript" OR CommandLine contains "vbscript" OR CommandLine contains "cscript" OR CommandLine contains "wmic " OR CommandLine contains "wmic.exe" OR CommandLine contains "regsvr32.exe" OR CommandLine contains "powershell" OR CommandLine contains "\\AppData\\")) AND ((Image contains "\\schtasks.exe") OR (OriginalFileName == "schtasks.exe")) AND ((CommandLine contains "once" AND CommandLine contains "00:00")))
