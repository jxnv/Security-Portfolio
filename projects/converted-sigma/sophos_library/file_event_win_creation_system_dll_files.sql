-- Title: Files With System DLL Name In Unsuspected Locations
-- ID: 13c02350-4177-4e45-ac17-cf7ca628ff5e
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-06-24
-- Tags: attack.stealth, attack.t1036.005
-- Description: Detects the creation of a file with the ".dll" extension that has the name of a System DLL in uncommon or unsuspected locations. (Outisde of "System32", "SysWOW64", etc.).
-- It is highly recommended to perform an initial baseline before using this rule in production.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetFilename ILIKE '%\\secur32.dll' OR TargetFilename ILIKE '%\\tdh.dll')) AND NOT (((TargetFilename ILIKE '%C:\\$WINDOWS.~BT\\%' OR TargetFilename ILIKE '%C:\\$WinREAgent\\%' OR TargetFilename ILIKE '%C:\\Windows\\SoftwareDistribution\\%' OR TargetFilename ILIKE '%C:\\Windows\\System32\\%' OR TargetFilename ILIKE '%C:\\Windows\\SysWOW64\\%' OR TargetFilename ILIKE '%C:\\Windows\\WinSxS\\%' OR TargetFilename ILIKE '%C:\\Windows\\uus\\%'))))
