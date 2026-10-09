-- Title: Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module
-- ID: 7034cbbb-cc55-4dc2-8dad-36c0b942e8f1
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Payload LIKE '%new-object%' AND Payload LIKE '%text.encoding]::ascii%') AND (Payload LIKE '%system.io.compression.deflatestream%' OR Payload LIKE '%system.io.streamreader%') AND Payload="*readtoend")
