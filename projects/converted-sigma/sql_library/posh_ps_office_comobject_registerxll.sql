-- Title: Code Executed Via Office Add-in XLL File
-- ID: 36fbec91-fa1b-4d5d-8df1-8d8edcb632ad
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2021-12-28
-- Tags: attack.persistence, attack.t1137.006
-- Description: Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system.
-- Office add-ins can be used to add functionality to Office programs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ScriptBlockText ILIKE '%new-object %' AND ScriptBlockText ILIKE '%-ComObject %' AND ScriptBlockText ILIKE '%.application%' AND ScriptBlockText ILIKE '%.RegisterXLL%'))
