-- Title: File With Uncommon Extension Created By An Office Application
-- ID: c7a74c80-ba5a-486e-9974-ab9e682bc5e4
-- Status: test
-- Level: high
-- Author: Vadim Khrykov (ThreatIntel), Cyb3rEng (Rule), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-08-23
-- Tags: attack.t1204.002, attack.execution
-- Description: Detects the creation of files with an executable or script extension by an Office application.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((Image ILIKE '%\\excel.exe' OR Image ILIKE '%\\msaccess.exe' OR Image ILIKE '%\\mspub.exe' OR Image ILIKE '%\\powerpnt.exe' OR Image ILIKE '%\\visio.exe' OR Image ILIKE '%\\winword.exe')) AND ((TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.cmd' OR TargetFilename ILIKE '%.com' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.ocx' OR TargetFilename ILIKE '%.proj' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.scf' OR TargetFilename ILIKE '%.scr' OR TargetFilename ILIKE '%.sys' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs' OR TargetFilename ILIKE '%.wsf' OR TargetFilename ILIKE '%.wsh'))) AND NOT ((TargetFilename ILIKE '%\\AppData\\Local\\assembly\\tmp\\%' AND TargetFilename ILIKE '%.dll')) AND NOT ((((TargetFilename ILIKE '%C:\\Users\\%' AND TargetFilename ILIKE '%\\AppData\\Local\\Microsoft\\Office\\%' AND TargetFilename ILIKE '%\\BackstageInAppNavCache\\%') AND TargetFilename ILIKE '%.com') OR (Image ILIKE '%\\winword.exe' AND TargetFilename ILIKE '%\\AppData\\Local\\Temp\\webexdelta\\%' AND (TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe')) OR ((TargetFilename ILIKE '%C:\\Users\\%' AND TargetFilename ILIKE '%\\AppData\\Local\\Microsoft\\Office\\%' AND TargetFilename ILIKE '%\\WebServiceCache\\AllUsers%') AND TargetFilename ILIKE '%.com'))))
