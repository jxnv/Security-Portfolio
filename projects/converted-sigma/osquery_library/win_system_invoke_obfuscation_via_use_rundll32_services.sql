-- Title: Invoke-Obfuscation Via Use Rundll32 - System
-- ID: 641a4bfb-c017-44f7-800c-2aee0184ce9b
-- Status: test
-- Level: high
-- Author: Nikita Nazarov, oscd.community
-- Date: 2020-10-09
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via use Rundll32 in Scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (Provider_Name = 'Service Control Manager' AND EventID = '7045' AND (ImagePath LIKE '%&&%' AND ImagePath LIKE '%rundll32%' AND ImagePath LIKE '%shell32.dll%' AND ImagePath LIKE '%shellexec_rundll%') AND (ImagePath LIKE '%value%' OR ImagePath LIKE '%invoke%' OR ImagePath LIKE '%comspec%' OR ImagePath LIKE '%iex%'))
