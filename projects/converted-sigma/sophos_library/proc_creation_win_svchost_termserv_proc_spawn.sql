-- Title: Terminal Service Process Spawn
-- ID: 1012f107-b8f1-4271-af30-5aed2de89b39
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2019-05-22
-- Tags: attack.initial-access, attack.t1190, attack.lateral-movement, attack.t1210, car.2013-07-002
-- Description: Detects a process spawned by the terminal service server process (this could be an indicator for an exploitation of CVE-2019-0708)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentCommandLine ILIKE '%\\svchost.exe%' AND ParentCommandLine ILIKE '%termsvcs%')) AND NOT ((((Image ILIKE '%\\rdpclip.exe' OR Image ILIKE '%:\\Windows\\System32\\csrss.exe' OR Image ILIKE '%:\\Windows\\System32\\wininit.exe' OR Image ILIKE '%:\\Windows\\System32\\winlogon.exe')) OR (Image IS NULL))))
