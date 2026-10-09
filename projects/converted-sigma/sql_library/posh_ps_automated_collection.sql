-- Title: Automated Collection Command PowerShell
-- ID: c1dda054-d638-4c16-afc8-53e007f3fbc5
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-07-28
-- Tags: attack.collection, attack.t1119
-- Description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ScriptBlockText ILIKE '%Get-ChildItem%' AND ScriptBlockText ILIKE '% -Recurse %' AND ScriptBlockText ILIKE '% -Include %')) AND ((ScriptBlockText ILIKE '%.doc%' OR ScriptBlockText ILIKE '%.docx%' OR ScriptBlockText ILIKE '%.xls%' OR ScriptBlockText ILIKE '%.xlsx%' OR ScriptBlockText ILIKE '%.ppt%' OR ScriptBlockText ILIKE '%.pptx%' OR ScriptBlockText ILIKE '%.rtf%' OR ScriptBlockText ILIKE '%.pdf%' OR ScriptBlockText ILIKE '%.txt%')))
