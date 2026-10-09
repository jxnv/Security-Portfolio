-- Title: Invoke-Obfuscation COMPRESS OBFUSCATION - System
-- ID: 175997c5-803c-4b08-8bb0-70b099f47595
-- Status: test
-- Level: medium
-- Author: Timur Zinniatullin, oscd.community
-- Date: 2020-10-18
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Provider_Name = 'Service Control Manager' AND EventID = 7045 AND (ImagePath ILIKE '%new-object%' AND ImagePath ILIKE '%text.encoding]::ascii%' AND ImagePath ILIKE '%readtoend%') AND (ImagePath ILIKE '%:system.io.compression.deflatestream%' OR ImagePath ILIKE '%system.io.streamreader%'))
