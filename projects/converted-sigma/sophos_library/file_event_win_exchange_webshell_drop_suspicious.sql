-- Title: Suspicious File Drop by Exchange
-- ID: 6b269392-9eba-40b5-acb6-55c882b20ba6
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-10-04
-- Tags: attack.persistence, attack.t1190, attack.initial-access, attack.t1505.003
-- Description: Detects suspicious file type dropped by an Exchange component in IIS
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\w3wp.exe' AND CommandLine ILIKE '%MSExchange%') AND ((TargetFilename ILIKE '%.aspx' OR TargetFilename ILIKE '%.asp' OR TargetFilename ILIKE '%.ashx' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.vbs')))
