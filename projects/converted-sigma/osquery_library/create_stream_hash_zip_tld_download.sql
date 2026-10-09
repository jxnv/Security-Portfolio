-- Title: Potentially Suspicious File Download From ZIP TLD
-- ID: 0bb4bbeb-fe52-4044-b40c-430a04577ebe
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2023-05-18
-- Tags: attack.stealth
-- Description: Detects the download of a file with a potentially suspicious extension from a .zip top level domain.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (Contents LIKE '%.zip/%' AND (TargetFilename LIKE '%.bat:Zone%' OR TargetFilename LIKE '%.dat:Zone%' OR TargetFilename LIKE '%.dll:Zone%' OR TargetFilename LIKE '%.doc:Zone%' OR TargetFilename LIKE '%.docm:Zone%' OR TargetFilename LIKE '%.exe:Zone%' OR TargetFilename LIKE '%.hta:Zone%' OR TargetFilename LIKE '%.pptm:Zone%' OR TargetFilename LIKE '%.ps1:Zone%' OR TargetFilename LIKE '%.rar:Zone%' OR TargetFilename LIKE '%.rtf:Zone%' OR TargetFilename LIKE '%.sct:Zone%' OR TargetFilename LIKE '%.vbe:Zone%' OR TargetFilename LIKE '%.vbs:Zone%' OR TargetFilename LIKE '%.ws:Zone%' OR TargetFilename LIKE '%.wsf:Zone%' OR TargetFilename LIKE '%.xll:Zone%' OR TargetFilename LIKE '%.xls:Zone%' OR TargetFilename LIKE '%.xlsm:Zone%' OR TargetFilename LIKE '%.zip:Zone%'))
