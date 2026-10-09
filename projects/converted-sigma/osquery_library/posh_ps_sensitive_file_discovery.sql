-- Title: Powershell Sensitive File Discovery
-- ID: 7d416556-6502-45b2-9bad-9d2f05f38997
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-09-16
-- Tags: attack.discovery, attack.t1083
-- Description: Detect adversaries enumerate sensitive files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ScriptBlockText LIKE '%ls%' OR ScriptBlockText LIKE '%get-childitem%' OR ScriptBlockText LIKE '%gci%')) AND ((ScriptBlockText LIKE '%.pass%' OR ScriptBlockText LIKE '%.kdbx%' OR ScriptBlockText LIKE '%.kdb%')) AND (ScriptBlockText LIKE '%-recurse%'))
