-- Title: LSASS Process Memory Dump Files
-- ID: a5a2d357-1ab8-4675-a967-ef9990a59391
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-11-15
-- Tags: attack.credential-access, attack.t1003.001
-- Description: Detects creation of files with names used by different memory dumping tools to create a memory dump of the LSASS process memory, which contains user credentials.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetFilename ILIKE '%\\Andrew.dmp' OR TargetFilename ILIKE '%\\Coredump.dmp' OR TargetFilename ILIKE '%\\lsass.dmp' OR TargetFilename ILIKE '%\\lsass.rar' OR TargetFilename ILIKE '%\\lsass.zip' OR TargetFilename ILIKE '%\\NotLSASS.zip' OR TargetFilename ILIKE '%\\PPLBlade.dmp' OR TargetFilename ILIKE '%\\rustive.dmp')) OR ((TargetFilename ILIKE '%\\lsass_2%' OR TargetFilename ILIKE '%\\lsassdmp%' OR TargetFilename ILIKE '%\\lsassdump%')) OR ((TargetFilename ILIKE '%\\lsass%' AND TargetFilename ILIKE '%.dmp%')) OR (TargetFilename ILIKE '%SQLDmpr%' AND TargetFilename ILIKE '%.mdmp') OR ((TargetFilename ILIKE '%\\nanodump%' OR TargetFilename ILIKE '%\\proc_%') AND TargetFilename ILIKE '%.dmp'))
