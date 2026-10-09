-- Title: Invoke-Obfuscation Via Use Rundll32 - PowerShell Module
-- ID: 88a22f69-62f9-4b8a-aa00-6b0212f2f05a
-- Status: test
-- Level: high
-- Author: Nikita Nazarov, oscd.community
-- Date: 2019-10-08
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via use Rundll32 in Scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Payload LIKE '%&&%' AND Payload LIKE '%rundll32%' AND Payload LIKE '%shell32.dll%' AND Payload LIKE '%shellexec_rundll%') AND (Payload LIKE '%value%' OR Payload LIKE '%invoke%' OR Payload LIKE '%comspec%' OR Payload LIKE '%iex%'))
