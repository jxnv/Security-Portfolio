-- Title: Failed Code Integrity Checks
-- ID: 470ec5fa-7b4e-4071-b200-4c753100f49b
-- Status: stable
-- Level: informational
-- Author: Thomas Patzke
-- Date: 2019-12-03
-- Tags: attack.stealth, attack.t1027.001
-- Description: Detects code integrity failures such as missing page hashes or corrupted drivers due unauthorized modification. This could be a sign of tampered binaries.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((EventID = 5038 OR EventID = 6281)) AND NOT ((((param1 ILIKE '%\\CSFalconServiceUninstallTool_%' OR param1 ILIKE '%\\Program Files\\CrowdStrike\\%' OR param1 ILIKE '%\\System32\\drivers\\CrowdStrike\\%' OR param1 ILIKE '%\\Windows\\System32\\ScriptControl64_%')) OR (param1 ILIKE '%\\Program Files\\Sophos\\%'))))
