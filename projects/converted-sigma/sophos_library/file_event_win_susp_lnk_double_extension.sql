-- Title: Suspicious LNK Double Extension File Created
-- ID: 3215aa19-f060-4332-86d5-5602511f3ca8
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2022-11-07
-- Tags: attack.stealth, attack.t1036.007
-- Description: Detects the creation of files with an "LNK" as a second extension. This is sometimes used by malware as a method to abuse the fact that Windows hides the "LNK" extension by default.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE '%.lnk' AND (TargetFilename ILIKE '%.doc.%' OR TargetFilename ILIKE '%.docx.%' OR TargetFilename ILIKE '%.jpg.%' OR TargetFilename ILIKE '%.pdf.%' OR TargetFilename ILIKE '%.ppt.%' OR TargetFilename ILIKE '%.pptx.%' OR TargetFilename ILIKE '%.xls.%' OR TargetFilename ILIKE '%.xlsx.%')) AND NOT ((TargetFilename ILIKE '%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\%')) AND NOT (((Image ILIKE '%\\excel.exe' AND TargetFilename ILIKE '%\\AppData\\Roaming\\Microsoft\\Excel%') OR (Image ILIKE '%\\powerpnt.exe' AND TargetFilename ILIKE '%\\AppData\\Roaming\\Microsoft\\PowerPoint%') OR ((Image ILIKE '%\\excel.exe' OR Image ILIKE '%\\powerpnt.exe' OR Image ILIKE '%\\winword.exe') AND TargetFilename ILIKE '%\\AppData\\Roaming\\Microsoft\\Office\\Recent\\%') OR (Image ILIKE '%\\winword.exe' AND TargetFilename ILIKE '%\\AppData\\Roaming\\Microsoft\\Word%'))))
