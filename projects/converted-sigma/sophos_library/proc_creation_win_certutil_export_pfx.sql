-- Title: Certificate Exported Via Certutil.EXE
-- ID: 3ffd6f51-e6c1-47b7-94b4-c1e61d4117c5
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-02-15
-- Tags: attack.stealth, attack.t1027
-- Description: Detects the execution of the certutil with the "exportPFX" flag which allows the utility to export certificates.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%-exportPFX %' OR CommandLine ILIKE '%/exportPFX %')) AND ((Image ILIKE '%\\certutil.exe') OR (OriginalFileName = 'CertUtil.exe')))
