-- Title: Arbitrary File Download Via MSOHTMED.EXE
-- ID: 459f2f98-397b-4a4a-9f47-6a5ec2f1c69d
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-19
-- Tags: attack.execution, attack.stealth, attack.t1218
-- Description: Detects usage of "MSOHTMED" to download arbitrary files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%ftp://%' OR CommandLine ILIKE '%http://%' OR CommandLine ILIKE '%https://%')) AND ((Image ILIKE '%\\MSOHTMED.exe') OR (OriginalFileName = 'MsoHtmEd.exe')))
