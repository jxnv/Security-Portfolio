-- Title: Suspicious Serv-U Process Pattern
-- ID: 58f4ea09-0fc2-4520-ba18-b85c540b0eaf
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-07-14
-- Tags: attack.credential-access, attack.t1555, cve.2021-35211
-- Description: Detects a suspicious process pattern which could be a sign of an exploited Serv-U service
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ParentImage ILIKE '%\\Serv-U.exe' AND (Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\sh.exe' OR Image ILIKE '%\\bash.exe' OR Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\msiexec.exe' OR Image ILIKE '%\\forfiles.exe' OR Image ILIKE '%\\scriptrunner.exe'))
