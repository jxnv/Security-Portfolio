-- Title: Suspicious File Created In PerfLogs
-- ID: bbb7e38c-0b41-4a11-b306-d2a457b7ac2b
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-05
-- Tags: attack.execution, attack.t1059
-- Description: Detects suspicious file based on their extension being created in "C:\PerfLogs\". Note that this directory mostly contains ".etl" files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (TargetFilename ILIKE 'C:\\PerfLogs\\%' AND (TargetFilename ILIKE '%.7z' OR TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.bin' OR TargetFilename ILIKE '%.chm' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.lnk' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.psm1' OR TargetFilename ILIKE '%.py' OR TargetFilename ILIKE '%.scr' OR TargetFilename ILIKE '%.sys' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs' OR TargetFilename ILIKE '%.zip'))
