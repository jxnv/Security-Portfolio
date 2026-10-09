-- Title: HackTool - Default PowerSploit/Empire Scheduled Task Creation
-- ID: 56c217c3-2de2-479b-990f-5c109ba8458f
-- Status: test
-- Level: high
-- Author: Markus Neis, @Karneades
-- Date: 2018-03-06
-- Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.s0111, attack.g0022, attack.g0060, car.2013-08-001, attack.t1053.005, attack.t1059.001
-- Description: Detects the creation of a schtask via PowerSploit or Empire Default Configuration.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((ParentImage="*\\powershell.exe" OR ParentImage="*\\pwsh.exe") AND Image="*\\schtasks.exe" AND (CommandLine LIKE '%/Create%' AND CommandLine LIKE '%powershell.exe -NonI%' AND CommandLine LIKE '%/TN Updater /TR%') AND (CommandLine LIKE '%/SC ONLOGON%' OR CommandLine LIKE '%/SC DAILY /ST%' OR CommandLine LIKE '%/SC ONIDLE%' OR CommandLine LIKE '%/SC HOURLY%'))
