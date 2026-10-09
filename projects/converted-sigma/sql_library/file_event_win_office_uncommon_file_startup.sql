-- Title: Uncommon File Created In Office Startup Folder
-- ID: a10a2c40-2c4d-49f8-b557-1a946bc55d9d
-- Status: test
-- Level: high
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-05
-- Tags: attack.resource-development, attack.t1587.001
-- Description: Detects the creation of a file with an uncommon extension in an Office application startup folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((((TargetFilename ILIKE '%\\Microsoft\\Word\\STARTUP%') OR ((TargetFilename ILIKE '%\\Office%' AND TargetFilename ILIKE '%\\Program Files%' AND TargetFilename ILIKE '%\\STARTUP%'))) AND NOT (((TargetFilename ILIKE '%.docb' OR TargetFilename ILIKE '%.docm' OR TargetFilename ILIKE '%.docx' OR TargetFilename ILIKE '%.dotm' OR TargetFilename ILIKE '%.mdb' OR TargetFilename ILIKE '%.mdw' OR TargetFilename ILIKE '%.pdf' OR TargetFilename ILIKE '%.wll' OR TargetFilename ILIKE '%.wwl')))) OR (((TargetFilename ILIKE '%\\Microsoft\\Excel\\XLSTART%') OR ((TargetFilename ILIKE '%\\Office%' AND TargetFilename ILIKE '%\\Program Files%' AND TargetFilename ILIKE '%\\XLSTART%'))) AND NOT (((TargetFilename ILIKE '%.xll' OR TargetFilename ILIKE '%.xls' OR TargetFilename ILIKE '%.xlsm' OR TargetFilename ILIKE '%.xlsx' OR TargetFilename ILIKE '%.xlt' OR TargetFilename ILIKE '%.xltm' OR TargetFilename ILIKE '%.xlw'))))) AND NOT ((((Image ILIKE '%:\\Program Files\\Microsoft Office\\%' OR Image ILIKE '%:\\Program Files (x86)\\Microsoft Office\\%') AND (Image ILIKE '%\\winword.exe' OR Image ILIKE '%\\excel.exe')) OR (Image ILIKE '%:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\%' AND Image ILIKE '%\\OfficeClickToRun.exe'))))
