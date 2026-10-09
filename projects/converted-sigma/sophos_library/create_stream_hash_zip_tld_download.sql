-- Title: Potentially Suspicious File Download From ZIP TLD
-- ID: 0bb4bbeb-fe52-4044-b40c-430a04577ebe
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2023-05-18
-- Tags: attack.stealth
-- Description: Detects the download of a file with a potentially suspicious extension from a .zip top level domain.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Contents ILIKE '%.zip/%' AND (TargetFilename ILIKE '%.bat:Zone%' OR TargetFilename ILIKE '%.dat:Zone%' OR TargetFilename ILIKE '%.dll:Zone%' OR TargetFilename ILIKE '%.doc:Zone%' OR TargetFilename ILIKE '%.docm:Zone%' OR TargetFilename ILIKE '%.exe:Zone%' OR TargetFilename ILIKE '%.hta:Zone%' OR TargetFilename ILIKE '%.pptm:Zone%' OR TargetFilename ILIKE '%.ps1:Zone%' OR TargetFilename ILIKE '%.rar:Zone%' OR TargetFilename ILIKE '%.rtf:Zone%' OR TargetFilename ILIKE '%.sct:Zone%' OR TargetFilename ILIKE '%.vbe:Zone%' OR TargetFilename ILIKE '%.vbs:Zone%' OR TargetFilename ILIKE '%.ws:Zone%' OR TargetFilename ILIKE '%.wsf:Zone%' OR TargetFilename ILIKE '%.xll:Zone%' OR TargetFilename ILIKE '%.xls:Zone%' OR TargetFilename ILIKE '%.xlsm:Zone%' OR TargetFilename ILIKE '%.zip:Zone%'))
