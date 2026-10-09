-- Title: Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell
-- ID: 20e5497e-331c-4cd5-8d36-935f6e2a9a07
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ScriptBlockText ILIKE '%new-object%' AND ScriptBlockText ILIKE '%text.encoding]::ascii%') AND (ScriptBlockText ILIKE '%system.io.compression.deflatestream%' OR ScriptBlockText ILIKE '%system.io.streamreader%') AND ScriptBlockText ILIKE '%readtoend')
