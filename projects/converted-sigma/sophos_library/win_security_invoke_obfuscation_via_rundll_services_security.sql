-- Title: Invoke-Obfuscation RUNDLL LAUNCHER - Security
-- ID: f241cf1b-3a6b-4e1a-b4f9-133c00dd95ca
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via RUNDLL LAUNCHER
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 4697 AND (ServiceFileName ILIKE '%rundll32.exe%' AND ServiceFileName ILIKE '%shell32.dll%' AND ServiceFileName ILIKE '%shellexec_rundll%' AND ServiceFileName ILIKE '%powershell%'))
