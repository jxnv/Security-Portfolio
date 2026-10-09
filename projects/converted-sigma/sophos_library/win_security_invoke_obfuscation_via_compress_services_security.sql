-- Title: Invoke-Obfuscation COMPRESS OBFUSCATION - Security
-- ID: 7a922f1b-2635-4d6c-91ef-af228b198ad3
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (EventID = 4697 AND (ServiceFileName ILIKE '%new-object%' AND ServiceFileName ILIKE '%text.encoding]::ascii%' AND ServiceFileName ILIKE '%readtoend%') AND (ServiceFileName ILIKE '%system.io.compression.deflatestream%' OR ServiceFileName ILIKE '%system.io.streamreader%'))
