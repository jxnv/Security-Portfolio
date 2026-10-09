-- Title: UAC Bypass Using EventVwr
-- ID: 63e4f530-65dc-49cc-8f80-ccfa95c69d43
-- Status: test
-- Level: high
-- Author: Antonio Cocomazzi (idea), Florian Roth (Nextron Systems)
-- Date: 2022-04-27
-- Tags: attack.privilege-escalation, attack.stealth
-- Description: Detects the pattern of a UAC bypass using Windows Event Viewer
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetFilename ILIKE '%\\Microsoft\\Event Viewer\\RecentViews' OR TargetFilename ILIKE '%\\Microsoft\\EventV~1\\RecentViews')) AND NOT (((Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%'))))
