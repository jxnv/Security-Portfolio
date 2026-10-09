-- Title: Automated Collection Command PowerShell
-- ID: c1dda054-d638-4c16-afc8-53e007f3fbc5
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-07-28
-- Tags: attack.collection, attack.t1119
-- Description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ScriptBlockText LIKE '%Get-ChildItem%' AND ScriptBlockText LIKE '% -Recurse %' AND ScriptBlockText LIKE '% -Include %')) AND ((ScriptBlockText LIKE '%.doc%' OR ScriptBlockText LIKE '%.docx%' OR ScriptBlockText LIKE '%.xls%' OR ScriptBlockText LIKE '%.xlsx%' OR ScriptBlockText LIKE '%.ppt%' OR ScriptBlockText LIKE '%.pptx%' OR ScriptBlockText LIKE '%.rtf%' OR ScriptBlockText LIKE '%.pdf%' OR ScriptBlockText LIKE '%.txt%')))
