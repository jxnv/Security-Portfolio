// Title: Suspicious Schtasks Schedule Types
// ID: 24c8392b-aa3c-46b7-a545-43f71657fe98
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
// Description: Detects scheduled task creations or modification on a suspicious schedule type
// Converted by: Sigma Universal SIEM/EDR CLI

((((Image="*\\schtasks.exe") OR (OriginalFileName == "schtasks.exe")) AND ((CommandLine contains " ONLOGON " OR CommandLine contains " ONSTART " OR CommandLine contains " ONCE " OR CommandLine contains " ONIDLE "))) AND NOT (((CommandLine contains "NT AUT" OR CommandLine contains " SYSTEM" OR CommandLine contains "HIGHEST"))))
