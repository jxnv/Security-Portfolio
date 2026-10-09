-- Title: Powershell Directory Enumeration
-- ID: 162e69a7-7981-4344-84a9-0f1c9a217a52
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-03-17
-- Tags: attack.discovery, attack.t1083
-- Description: Detects technique used by MAZE ransomware to enumerate directories using Powershell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ScriptBlockText ILIKE '%foreach%' AND ScriptBlockText ILIKE '%Get-ChildItem%' AND ScriptBlockText ILIKE '%-Path %' AND ScriptBlockText ILIKE '%-ErrorAction %' AND ScriptBlockText ILIKE '%SilentlyContinue%' AND ScriptBlockText ILIKE '%Out-File %' AND ScriptBlockText ILIKE '%-append%'))
