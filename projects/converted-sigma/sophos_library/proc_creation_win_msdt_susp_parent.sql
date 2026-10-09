-- Title: Suspicious MSDT Parent Process
-- ID: 7a74da6b-ea76-47db-92cc-874ad90df734
-- Status: test
-- Level: high
-- Author: Nextron Systems
-- Date: 2022-06-01
-- Tags: attack.stealth, attack.t1036, attack.t1218
-- Description: Detects msdt.exe executed by a suspicious parent as seen in CVE-2022-30190 / Follina exploitation
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\msdt.exe') OR (OriginalFileName = 'msdt.exe')) AND ((ParentImage ILIKE '%\\cmd.exe' OR ParentImage ILIKE '%\\cscript.exe' OR ParentImage ILIKE '%\\mshta.exe' OR ParentImage ILIKE '%\\powershell.exe' OR ParentImage ILIKE '%\\pwsh.exe' OR ParentImage ILIKE '%\\regsvr32.exe' OR ParentImage ILIKE '%\\rundll32.exe' OR ParentImage ILIKE '%\\schtasks.exe' OR ParentImage ILIKE '%\\wmic.exe' OR ParentImage ILIKE '%\\wscript.exe' OR ParentImage ILIKE '%\\wsl.exe')))
