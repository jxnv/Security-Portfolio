-- Title: Invoke-Obfuscation Via Use Rundll32 - Security
-- ID: cd0f7229-d16f-42de-8fe3-fba365fbcb3a
-- Status: test
-- Level: high
-- Author: Nikita Nazarov, oscd.community
-- Date: 2020-10-09
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via use Rundll32 in Scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (EventID = '4697' AND (ServiceFileName LIKE '%&&%' AND ServiceFileName LIKE '%rundll32%' AND ServiceFileName LIKE '%shell32.dll%' AND ServiceFileName LIKE '%shellexec_rundll%') AND (ServiceFileName LIKE '%value%' OR ServiceFileName LIKE '%invoke%' OR ServiceFileName LIKE '%comspec%' OR ServiceFileName LIKE '%iex%'))
