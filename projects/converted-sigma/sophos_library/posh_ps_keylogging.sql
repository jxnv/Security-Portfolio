-- Title: Powershell Keylogging
-- ID: 34f90d3c-c297-49e9-b26d-911b05a4866c
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-07-30
-- Tags: attack.credential-access, attack.collection, attack.t1056.001
-- Description: Adversaries may log user keystrokes to intercept credentials as the user types them.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ScriptBlockText ILIKE '%Get-Keystrokes%') OR ((ScriptBlockText ILIKE '%Get-ProcAddress user32.dll GetAsyncKeyState%' AND ScriptBlockText ILIKE '%Get-ProcAddress user32.dll GetForegroundWindow%')))
