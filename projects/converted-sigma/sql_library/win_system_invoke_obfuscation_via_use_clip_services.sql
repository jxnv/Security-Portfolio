-- Title: Invoke-Obfuscation Via Use Clip - System
-- ID: 63e3365d-4824-42d8-8b82-e56810fefa0c
-- Status: test
-- Level: high
-- Author: Nikita Nazarov, oscd.community
-- Date: 2020-10-09
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via use Clip.exe in Scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Provider_Name = 'Service Control Manager' AND EventID = 7045 AND ImagePath ILIKE '%(Clipboard|i%')
