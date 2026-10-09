-- Title: Suspicious Child Process Of Manage Engine ServiceDesk
-- ID: cea2b7ea-792b-405f-95a1-b903ea06458f
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2023-01-18
-- Tags: attack.command-and-control, attack.t1102
-- Description: Detects suspicious child processes of the "Manage Engine ServiceDesk Plus" Java web service
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((ParentImage LIKE '%\\ManageEngine\\ServiceDesk\\%' AND ParentImage LIKE '%\\java.exe%') AND (Image="*\\AppVLP.exe" OR Image="*\\bash.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\calc.exe" OR Image="*\\certutil.exe" OR Image="*\\cscript.exe" OR Image="*\\curl.exe" OR Image="*\\forfiles.exe" OR Image="*\\mftrace.exe" OR Image="*\\mshta.exe" OR Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\notepad.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\query.exe" OR Image="*\\reg.exe" OR Image="*\\schtasks.exe" OR Image="*\\scrcons.exe" OR Image="*\\sh.exe" OR Image="*\\systeminfo.exe" OR Image="*\\whoami.exe" OR Image="*\\wmic.exe" OR Image="*\\wscript.exe")) AND NOT (((Image="*\\net.exe" OR Image="*\\net1.exe") AND CommandLine LIKE '% stop%')))
