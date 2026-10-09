-- Title: Suspicious Appended Extension
-- ID: e3f673b3-65d1-4d80-9146-466f8b63fa99
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-07-16
-- Tags: attack.impact, attack.t1486
-- Description: Detects file renames where the target filename uses an uncommon double extension. Could indicate potential ransomware activity renaming files and adding a custom extension to the encrypted files, such as ".jpg.crypted", ".docx.locky", etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((SourceFilename="*.doc" OR SourceFilename="*.docx" OR SourceFilename="*.jpeg" OR SourceFilename="*.jpg" OR SourceFilename="*.lnk" OR SourceFilename="*.pdf" OR SourceFilename="*.png" OR SourceFilename="*.pst" OR SourceFilename="*.rtf" OR SourceFilename="*.xls" OR SourceFilename="*.xlsx") AND (TargetFilename LIKE '%.doc.%' OR TargetFilename LIKE '%.docx.%' OR TargetFilename LIKE '%.jpeg.%' OR TargetFilename LIKE '%.jpg.%' OR TargetFilename LIKE '%.lnk.%' OR TargetFilename LIKE '%.pdf.%' OR TargetFilename LIKE '%.png.%' OR TargetFilename LIKE '%.pst.%' OR TargetFilename LIKE '%.rtf.%' OR TargetFilename LIKE '%.xls.%' OR TargetFilename LIKE '%.xlsx.%')) AND NOT (((TargetFilename="*.backup" OR TargetFilename="*.bak" OR TargetFilename="*.old" OR TargetFilename="*.orig" OR TargetFilename="*.temp" OR TargetFilename="*.tmp"))) AND NOT ((TargetFilename LIKE '%:\\ProgramData\\Anaconda3\\%' AND TargetFilename="*.c~")))
