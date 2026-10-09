-- Title: Suspicious Appended Extension
-- ID: e3f673b3-65d1-4d80-9146-466f8b63fa99
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-07-16
-- Tags: attack.impact, attack.t1486
-- Description: Detects file renames where the target filename uses an uncommon double extension. Could indicate potential ransomware activity renaming files and adding a custom extension to the encrypted files, such as ".jpg.crypted", ".docx.locky", etc.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((SourceFilename ILIKE '%.doc' OR SourceFilename ILIKE '%.docx' OR SourceFilename ILIKE '%.jpeg' OR SourceFilename ILIKE '%.jpg' OR SourceFilename ILIKE '%.lnk' OR SourceFilename ILIKE '%.pdf' OR SourceFilename ILIKE '%.png' OR SourceFilename ILIKE '%.pst' OR SourceFilename ILIKE '%.rtf' OR SourceFilename ILIKE '%.xls' OR SourceFilename ILIKE '%.xlsx') AND (TargetFilename ILIKE '%.doc.%' OR TargetFilename ILIKE '%.docx.%' OR TargetFilename ILIKE '%.jpeg.%' OR TargetFilename ILIKE '%.jpg.%' OR TargetFilename ILIKE '%.lnk.%' OR TargetFilename ILIKE '%.pdf.%' OR TargetFilename ILIKE '%.png.%' OR TargetFilename ILIKE '%.pst.%' OR TargetFilename ILIKE '%.rtf.%' OR TargetFilename ILIKE '%.xls.%' OR TargetFilename ILIKE '%.xlsx.%')) AND NOT (((TargetFilename ILIKE '%.backup' OR TargetFilename ILIKE '%.bak' OR TargetFilename ILIKE '%.old' OR TargetFilename ILIKE '%.orig' OR TargetFilename ILIKE '%.temp' OR TargetFilename ILIKE '%.tmp'))) AND NOT ((TargetFilename ILIKE '%:\\ProgramData\\Anaconda3\\%' AND TargetFilename ILIKE '%.c~')))
