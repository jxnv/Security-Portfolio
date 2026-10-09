-- Title: Renamed Plink Execution
-- ID: 1c12727d-02bf-45ff-a9f3-d49806a3cf43
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-06
-- Tags: attack.stealth, attack.t1036
-- Description: Detects the execution of a renamed version of the Plink binary
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((OriginalFileName = 'Plink') OR ((CommandLine ILIKE '% -l forward%' AND CommandLine ILIKE '% -P %' AND CommandLine ILIKE '% -R %'))) AND NOT ((Image ILIKE '%\\plink.exe')))
