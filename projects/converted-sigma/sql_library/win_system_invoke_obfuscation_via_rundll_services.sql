-- Title: Invoke-Obfuscation RUNDLL LAUNCHER - System
-- ID: 11b52f18-aaec-4d60-9143-5dd8cc4706b9
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via RUNDLL LAUNCHER
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Provider_Name = 'Service Control Manager' AND EventID = 7045 AND (ImagePath ILIKE '%rundll32.exe%' AND ImagePath ILIKE '%shell32.dll%' AND ImagePath ILIKE '%shellexec_rundll%' AND ImagePath ILIKE '%powershell%'))
