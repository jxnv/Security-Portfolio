-- Title: Uncommon File Created In Office Startup Folder
-- ID: a10a2c40-2c4d-49f8-b557-1a946bc55d9d
-- Status: test
-- Level: high
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-05
-- Tags: attack.resource-development, attack.t1587.001
-- Description: Detects the creation of a file with an uncommon extension in an Office application startup folder
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((((TargetFilename LIKE '%\\Microsoft\\Word\\STARTUP%') OR ((TargetFilename LIKE '%\\Office%' AND TargetFilename LIKE '%\\Program Files%' AND TargetFilename LIKE '%\\STARTUP%'))) AND NOT (((TargetFilename="*.docb" OR TargetFilename="*.docm" OR TargetFilename="*.docx" OR TargetFilename="*.dotm" OR TargetFilename="*.mdb" OR TargetFilename="*.mdw" OR TargetFilename="*.pdf" OR TargetFilename="*.wll" OR TargetFilename="*.wwl")))) OR (((TargetFilename LIKE '%\\Microsoft\\Excel\\XLSTART%') OR ((TargetFilename LIKE '%\\Office%' AND TargetFilename LIKE '%\\Program Files%' AND TargetFilename LIKE '%\\XLSTART%'))) AND NOT (((TargetFilename="*.xll" OR TargetFilename="*.xls" OR TargetFilename="*.xlsm" OR TargetFilename="*.xlsx" OR TargetFilename="*.xlt" OR TargetFilename="*.xltm" OR TargetFilename="*.xlw"))))) AND NOT ((((Image LIKE '%:\\Program Files\\Microsoft Office\\%' OR Image LIKE '%:\\Program Files (x86)\\Microsoft Office\\%') AND (Image="*\\winword.exe" OR Image="*\\excel.exe")) OR (Image LIKE '%:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\%' AND Image="*\\OfficeClickToRun.exe"))))
