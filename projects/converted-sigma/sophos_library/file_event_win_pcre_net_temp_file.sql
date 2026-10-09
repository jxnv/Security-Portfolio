-- Title: PCRE.NET Package Temp Files
-- ID: 6e90ae7a-7cd3-473f-a035-4ebb72d961da
-- Status: test
-- Level: high
-- Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date: 2020-10-29
-- Tags: attack.execution, attack.t1059
-- Description: Detects processes creating temp files related to PCRE.NET package
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (TargetFilename ILIKE '%\\AppData\\Local\\Temp\\ba9ea7344a4a5f591d6e5dc32a13494b\\%')
