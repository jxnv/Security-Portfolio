-- Title: Invoke-Obfuscation Via Use Clip - Security
-- ID: 1a0a2ff1-611b-4dac-8216-8a7b47c618a6
-- Status: test
-- Level: high
-- Author: Nikita Nazarov, oscd.community
-- Date: 2020-10-09
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via use Clip.exe in Scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (EventID = 4697 AND ServiceFileName ILIKE '%(Clipboard|i%')
