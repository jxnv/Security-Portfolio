-- Title: Invoke-Obfuscation Via Use Rundll32 - PowerShell
-- ID: a5a30a6e-75ca-4233-8b8c-42e0f2037d3b
-- Status: test
-- Level: high
-- Author: Nikita Nazarov, oscd.community
-- Date: 2019-10-08
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via use Rundll32 in Scripts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%&&%' AND ScriptBlockText LIKE '%rundll32%' AND ScriptBlockText LIKE '%shell32.dll%' AND ScriptBlockText LIKE '%shellexec_rundll%') AND (ScriptBlockText LIKE '%value%' OR ScriptBlockText LIKE '%invoke%' OR ScriptBlockText LIKE '%comspec%' OR ScriptBlockText LIKE '%iex%'))
