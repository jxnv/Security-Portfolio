-- Title: Invoke-Obfuscation Via Use MSHTA - Security
-- ID: 9b8d9203-4e0f-4cd9-bb06-4cc4ea6d0e9a
-- Status: test
-- Level: high
-- Author: Nikita Nazarov, oscd.community
-- Date: 2020-10-09
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via use MSHTA in Scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 4697 AND (ServiceFileName ILIKE '%mshta%' AND ServiceFileName ILIKE '%vbscript:createobject%' AND ServiceFileName ILIKE '%.run%' AND ServiceFileName ILIKE '%window.close%'))
