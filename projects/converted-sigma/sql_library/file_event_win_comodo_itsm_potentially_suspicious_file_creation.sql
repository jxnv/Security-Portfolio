-- Title: Potentially Suspicious File Creation by OpenEDR's ITSMService
-- ID: 9e4b7d3a-6f2c-4e9a-8d1b-3c5e7a9f2b4d
-- Status: experimental
-- Level: medium
-- Author: @kostastsale
-- Date: 2026-02-19
-- Tags: attack.command-and-control, attack.t1105, attack.lateral-movement, attack.t1570, attack.t1219
-- Description: Detects the creation of potentially suspicious files by OpenEDR's ITSMService process.
-- The ITSMService is responsible for remote management operations and can create files on the system through the Process Explorer or file management features.
-- While legitimate for IT operations, creation of executable or script files could indicate unauthorized file uploads, data staging, or malicious file deployment.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\COMODO\\Endpoint Manager\\ITSMService.exe') AND ((TargetFilename ILIKE '%.7z' OR TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.cmd' OR TargetFilename ILIKE '%.com' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.js' OR TargetFilename ILIKE '%.pif' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.rar' OR TargetFilename ILIKE '%.scr' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs' OR TargetFilename ILIKE '%.zip')))
