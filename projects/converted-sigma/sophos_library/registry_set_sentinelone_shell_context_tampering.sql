-- Title: Potential SentinelOne Shell Context Menu Scan Command Tampering
-- ID: 6c304b02-06e6-402d-8be4-d5833cdf8198
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-03-06
-- Tags: attack.persistence
-- Description: Detects potentially suspicious changes to the SentinelOne context menu scan command by a process other than SentinelOne.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetObject ILIKE '%\\shell\\SentinelOneScan\\command\\%') AND NOT ((((Image ILIKE '%C:\\Program Files\\SentinelOne\\' OR Image ILIKE '%C:\\Program Files (x86)\\SentinelOne\\')) OR ((Details ILIKE 'C:\\Program Files\\SentinelOne\\Sentinel Agent%' OR Details ILIKE 'C:\\Program Files (x86)\\SentinelOne\\Sentinel Agent%') AND Details ILIKE '%\\SentinelScanFromContextMenu.exe%'))))
