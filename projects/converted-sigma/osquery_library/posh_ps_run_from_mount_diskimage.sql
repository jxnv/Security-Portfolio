-- Title: Suspicious Invoke-Item From Mount-DiskImage
-- ID: 902cedee-0398-4e3a-8183-6f3a89773a96
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-02-01
-- Tags: attack.defense-impairment, attack.t1553.005
-- Description: Adversaries may abuse container files such as disk image (.iso, .vhd) file formats to deliver malicious payloads that may not be tagged with MOTW.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((ScriptBlockText LIKE '%Mount-DiskImage %' AND ScriptBlockText LIKE '%-ImagePath %' AND ScriptBlockText LIKE '%Get-Volume%' AND ScriptBlockText LIKE '%.DriveLetter%' AND ScriptBlockText LIKE '%invoke-item %' AND ScriptBlockText LIKE '%):\\%'))
