-- Title: Arbitrary File Download Via ConfigSecurityPolicy.EXE
-- ID: 1f0f6176-6482-4027-b151-00071af39d7e
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-11-26
-- Tags: attack.exfiltration, attack.t1567
-- Description: Detects the execution of "ConfigSecurityPolicy.EXE", a binary part of Windows Defender used to manage settings in Windows Defender.
-- Users can configure different pilot collections for each of the co-management workloads.
-- It can be abused by attackers in order to upload or download files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%ConfigSecurityPolicy.exe%') OR (Image="*\\ConfigSecurityPolicy.exe") OR (OriginalFileName = 'ConfigSecurityPolicy.exe')) AND ((CommandLine LIKE '%ftp://%' OR CommandLine LIKE '%http://%' OR CommandLine LIKE '%https://%')))
