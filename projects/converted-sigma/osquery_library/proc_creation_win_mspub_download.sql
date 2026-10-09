-- Title: Arbitrary File Download Via MSPUB.EXE
-- ID: 3b3c7f55-f771-4dd6-8a6e-08d057a17caf
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-19
-- Tags: attack.execution, attack.stealth, attack.t1218
-- Description: Detects usage of "MSPUB" (Microsoft Publisher) to download arbitrary files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%ftp://%' OR CommandLine LIKE '%http://%' OR CommandLine LIKE '%https://%')) AND ((Image="*\\MSPUB.exe") OR (OriginalFileName = 'MSPUB.exe')))
