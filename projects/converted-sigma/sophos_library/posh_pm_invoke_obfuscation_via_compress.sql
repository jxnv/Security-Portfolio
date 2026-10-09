-- Title: Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module
-- ID: 7034cbbb-cc55-4dc2-8dad-36c0b942e8f1
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Payload ILIKE '%new-object%' AND Payload ILIKE '%text.encoding]::ascii%') AND (Payload ILIKE '%system.io.compression.deflatestream%' OR Payload ILIKE '%system.io.streamreader%') AND Payload ILIKE '%readtoend')
