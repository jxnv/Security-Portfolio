-- Title: Office Macro File Creation
-- ID: 91174a41-dc8f-401b-be89-7bfc140612a0
-- Status: test
-- Level: low
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-01-23
-- Tags: attack.initial-access, attack.t1566.001
-- Description: Detects the creation of a new office macro files on the systems
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetFilename ILIKE '%.docm' OR TargetFilename ILIKE '%.dotm' OR TargetFilename ILIKE '%.xlsm' OR TargetFilename ILIKE '%.xltm' OR TargetFilename ILIKE '%.potm' OR TargetFilename ILIKE '%.pptm')) AND NOT (((Image ILIKE 'C:\\Program Files\\Microsoft Office\\%' OR Image ILIKE 'C:\\Program Files (x86)\\Microsoft Office\\%') AND (Image ILIKE '%\\WINWORD.EXE' OR Image ILIKE '%\\EXCEL.EXE' OR Image ILIKE '%\\POWERPNT.EXE') AND TargetFilename ILIKE '%\\~$%')))
