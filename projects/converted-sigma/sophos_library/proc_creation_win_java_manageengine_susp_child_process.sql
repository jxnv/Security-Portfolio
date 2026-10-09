-- Title: Suspicious Child Process Of Manage Engine ServiceDesk
-- ID: cea2b7ea-792b-405f-95a1-b903ea06458f
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2023-01-18
-- Tags: attack.command-and-control, attack.t1102
-- Description: Detects suspicious child processes of the "Manage Engine ServiceDesk Plus" Java web service
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentImage ILIKE '%\\ManageEngine\\ServiceDesk\\%' AND ParentImage ILIKE '%\\java.exe%') AND (Image ILIKE '%\\AppVLP.exe' OR Image ILIKE '%\\bash.exe' OR Image ILIKE '%\\bitsadmin.exe' OR Image ILIKE '%\\calc.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\curl.exe' OR Image ILIKE '%\\forfiles.exe' OR Image ILIKE '%\\mftrace.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe' OR Image ILIKE '%\\notepad.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\query.exe' OR Image ILIKE '%\\reg.exe' OR Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\scrcons.exe' OR Image ILIKE '%\\sh.exe' OR Image ILIKE '%\\systeminfo.exe' OR Image ILIKE '%\\whoami.exe' OR Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\wscript.exe')) AND NOT (((Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe') AND CommandLine ILIKE '% stop%')))
