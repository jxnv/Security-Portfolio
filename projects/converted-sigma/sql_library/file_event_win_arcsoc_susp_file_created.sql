-- Title: Suspicious File Created by ArcSOC.exe
-- ID: e890acee-d488-420e-8f20-d9b19b3c3d43
-- Status: experimental
-- Level: high
-- Author: Micah Babinski
-- Date: 2025-11-25
-- Tags: attack.command-and-control, attack.persistence, attack.initial-access, attack.execution, attack.stealth, attack.t1127, attack.t1105, attack.t1133
-- Description: Detects instances where the ArcGIS Server process ArcSOC.exe, which hosts REST services running on an ArcGIS
-- server, creates a file with suspicious file type, indicating that it may be an executable, script file,
-- or otherwise unusual.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Image ILIKE '%\\ArcSOC.exe' AND (TargetFilename ILIKE '%.ahk' OR TargetFilename ILIKE '%.aspx' OR TargetFilename ILIKE '%.au3' OR TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.cmd' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.js' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.py' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs' OR TargetFilename ILIKE '%.wsf'))
