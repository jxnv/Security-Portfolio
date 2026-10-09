-- Title: Troubleshooting Pack Cmdlet Execution
-- ID: 03409c93-a7c7-49ba-9a4c-a00badf2a153
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-21
-- Tags: attack.stealth, attack.t1202
-- Description: Detects execution of "TroubleshootingPack" cmdlets to leverage CVE-2022-30190 or action similar to "msdt" lolbin (as described in LOLBAS)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ScriptBlockText ILIKE '%Invoke-TroubleshootingPack%' AND ScriptBlockText ILIKE '%C:\\Windows\\Diagnostics\\System\\PCW%' AND ScriptBlockText ILIKE '%-AnswerFile%' AND ScriptBlockText ILIKE '%-Unattended%'))
