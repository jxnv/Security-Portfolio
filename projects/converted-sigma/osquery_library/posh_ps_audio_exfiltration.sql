-- Title: Potential Data Exfiltration Via Audio File
-- ID: e4f93c99-396f-47c8-bb0f-201b1fa69034
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-16
-- Tags: attack.exfiltration
-- Description: Detects potential exfiltration attempt via audio file using PowerShell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ScriptBlockText LIKE '%[System.Math]::%' AND ScriptBlockText LIKE '%[IO.FileMode]::%' AND ScriptBlockText LIKE '%BinaryWriter%')) AND ((ScriptBlockText LIKE '%0x52%' AND ScriptBlockText LIKE '%0x49%' AND ScriptBlockText LIKE '%0x46%' AND ScriptBlockText LIKE '%0x57%' AND ScriptBlockText LIKE '%0x41%' AND ScriptBlockText LIKE '%0x56%' AND ScriptBlockText LIKE '%0x45%' AND ScriptBlockText LIKE '%0xAC%')))
