-- Title: Registry Persistence via Service in Safe Mode
-- ID: 1547e27c-3974-43e2-a7d7-7f484fb928ec
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2022-04-04
-- Tags: attack.stealth, attack.t1564.001
-- Description: Detects the modification of the registry to allow a driver or service to persist in Safe Mode.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetObject ILIKE '%\\Control\\SafeBoot\\Minimal\\%' OR TargetObject ILIKE '%\\Control\\SafeBoot\\Network\\%') AND TargetObject ILIKE '%\\(Default)' AND Details = 'Service') AND NOT (((Image = 'C:\\Hexnode\\Hexnode Agent\\Current\\HexnodeAgent.exe' AND (TargetObject ILIKE '%\\Control\\SafeBoot\\Minimal\\Hexnode Updater\\(Default)' OR TargetObject ILIKE '%\\Control\\SafeBoot\\Network\\Hexnode Updater\\(Default)' OR TargetObject ILIKE '%\\Control\\SafeBoot\\Minimal\\Hexnode Agent\\(Default)' OR TargetObject ILIKE '%\\Control\\SafeBoot\\Network\\Hexnode Agent\\(Default)') AND Details = 'Service') OR (Image ILIKE '%\\MBAMInstallerService.exe' AND TargetObject ILIKE '%\\MBAMService\\(Default)' AND Details = 'Service') OR (Image = 'C:\\WINDOWS\\system32\\msiexec.exe' AND (TargetObject ILIKE '%\\Control\\SafeBoot\\Minimal\\SAVService\\(Default)' OR TargetObject ILIKE '%\\Control\\SafeBoot\\Network\\SAVService\\(Default)')))))
