// Title: HackTool - SharPersist Execution
// ID: 26488ad0-f9fd-4536-876f-52fea846a2e4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-09-15
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1053
// Description: Detects the execution of the hacktool SharPersist - used to deploy various different kinds of persistence mechanisms
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " -t schtask -c " OR CommandLine contains " -t startupfolder -c ")) OR ((CommandLine contains " -t reg -c " AND CommandLine contains " -m add")) OR ((CommandLine contains " -t service -c " AND CommandLine contains " -m add")) OR ((CommandLine contains " -t schtask -c " AND CommandLine contains " -m add")) OR ((Image="*\\SharPersist.exe") OR (Product == "SharPersist")))
