-- Title: Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell
-- ID: e6cb92b4-b470-4eb8-8a9d-d63e8583aae0
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via RUNDLL LAUNCHER
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%rundll32.exe%' AND ScriptBlockText LIKE '%shell32.dll%' AND ScriptBlockText LIKE '%shellexec_rundll%' AND ScriptBlockText LIKE '%powershell%'))
