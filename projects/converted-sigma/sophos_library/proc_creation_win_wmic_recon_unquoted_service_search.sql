-- Title: Potential Unquoted Service Path Reconnaissance Via Wmic.EXE
-- ID: 68bcd73b-37ef-49cb-95fc-edc809730be6
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-20
-- Tags: attack.execution, attack.t1047
-- Description: Detects known WMI recon method to look for unquoted service paths using wmic. Often used by pentester and attacker enumeration scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% service get %' AND CommandLine ILIKE '%name,displayname,pathname,startmode%')) AND ((OriginalFileName = 'wmic.exe') OR (Image ILIKE '%\\WMIC.exe')))
