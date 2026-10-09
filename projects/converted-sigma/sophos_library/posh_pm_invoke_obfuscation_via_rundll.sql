-- Title: Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module
-- ID: a23791fe-8846-485a-b16b-ca691e1b03d4
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via RUNDLL LAUNCHER
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Payload ILIKE '%rundll32.exe%' AND Payload ILIKE '%shell32.dll%' AND Payload ILIKE '%shellexec_rundll%' AND Payload ILIKE '%powershell%'))
