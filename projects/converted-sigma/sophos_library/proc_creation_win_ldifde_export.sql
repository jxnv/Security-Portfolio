-- Title: Active Directory Structure Export Via Ldifde.EXE
-- ID: 4f7a6757-ff79-46db-9687-66501a02d9ec
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-03-14
-- Tags: attack.exfiltration
-- Description: Detects the execution of "ldifde.exe" in order to export organizational Active Directory structure.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%-f%') AND ((Image ILIKE '%\\ldifde.exe') OR (OriginalFileName = 'ldifde.exe'))) AND NOT ((CommandLine ILIKE '% -i%')))
