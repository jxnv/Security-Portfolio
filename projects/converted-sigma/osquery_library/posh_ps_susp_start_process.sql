-- Title: Suspicious Start-Process PassThru
-- ID: 0718cd72-f316-4aa2-988f-838ea8533277
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-01-15
-- Tags: attack.stealth, attack.t1036.003
-- Description: Powershell use PassThru option to start in background
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ScriptBlockText LIKE '%Start-Process %' OR ScriptBlockText LIKE '%saps %')) AND ((ScriptBlockText LIKE '%-PassThru %' AND ScriptBlockText LIKE '%-FilePath %')))
