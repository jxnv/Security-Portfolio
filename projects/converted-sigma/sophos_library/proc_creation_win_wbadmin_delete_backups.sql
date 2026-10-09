-- Title: Windows Backup Deleted Via Wbadmin.EXE
-- ID: 89f75308-5b1b-4390-b2d8-d6b2340efaf8
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-12-13
-- Tags: attack.impact, attack.t1490
-- Description: Detects the deletion of backups or system state backups via "wbadmin.exe".
-- This technique is used by numerous ransomware families and actors.
-- This may only be successful on server platforms that have Windows Backup enabled.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%delete %' AND CommandLine ILIKE '%backup%')) AND ((Image ILIKE '%\\wbadmin.exe') OR (OriginalFileName = 'WBADMIN.EXE'))) AND NOT ((CommandLine ILIKE '%keepVersions:0%')))
