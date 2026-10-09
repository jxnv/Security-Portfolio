-- Title: Arbitrary File Download Via MSPUB.EXE
-- ID: 3b3c7f55-f771-4dd6-8a6e-08d057a17caf
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-19
-- Tags: attack.execution, attack.stealth, attack.t1218
-- Description: Detects usage of "MSPUB" (Microsoft Publisher) to download arbitrary files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%ftp://%' OR CommandLine ILIKE '%http://%' OR CommandLine ILIKE '%https://%')) AND ((Image ILIKE '%\\MSPUB.exe') OR (OriginalFileName = 'MSPUB.exe')))
