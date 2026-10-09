-- Title: Invoke-Obfuscation Via Use Rundll32 - System
-- ID: 641a4bfb-c017-44f7-800c-2aee0184ce9b
-- Status: test
-- Level: high
-- Author: Nikita Nazarov, oscd.community
-- Date: 2020-10-09
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via use Rundll32 in Scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Provider_Name = 'Service Control Manager' AND EventID = 7045 AND (ImagePath ILIKE '%&&%' AND ImagePath ILIKE '%rundll32%' AND ImagePath ILIKE '%shell32.dll%' AND ImagePath ILIKE '%shellexec_rundll%') AND (ImagePath ILIKE '%value%' OR ImagePath ILIKE '%invoke%' OR ImagePath ILIKE '%comspec%' OR ImagePath ILIKE '%iex%'))
