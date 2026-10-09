-- Title: Suspicious LNK Double Extension File Created
-- ID: 3215aa19-f060-4332-86d5-5602511f3ca8
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2022-11-07
-- Tags: attack.stealth, attack.t1036.007
-- Description: Detects the creation of files with an "LNK" as a second extension. This is sometimes used by malware as a method to abuse the fact that Windows hides the "LNK" extension by default.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetFilename="*.lnk" AND (TargetFilename LIKE '%.doc.%' OR TargetFilename LIKE '%.docx.%' OR TargetFilename LIKE '%.jpg.%' OR TargetFilename LIKE '%.pdf.%' OR TargetFilename LIKE '%.ppt.%' OR TargetFilename LIKE '%.pptx.%' OR TargetFilename LIKE '%.xls.%' OR TargetFilename LIKE '%.xlsx.%')) AND NOT ((TargetFilename LIKE '%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\%')) AND NOT (((Image="*\\excel.exe" AND TargetFilename LIKE '%\\AppData\\Roaming\\Microsoft\\Excel%') OR (Image="*\\powerpnt.exe" AND TargetFilename LIKE '%\\AppData\\Roaming\\Microsoft\\PowerPoint%') OR ((Image="*\\excel.exe" OR Image="*\\powerpnt.exe" OR Image="*\\winword.exe") AND TargetFilename LIKE '%\\AppData\\Roaming\\Microsoft\\Office\\Recent\\%') OR (Image="*\\winword.exe" AND TargetFilename LIKE '%\\AppData\\Roaming\\Microsoft\\Word%'))))
