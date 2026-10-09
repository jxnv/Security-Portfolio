-- Title: Suspicious Autorun Registry Modified via WMI
-- ID: c80e66d8-1780-48a9-b412-46663fd21ac0
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-02-17
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1547.001, attack.t1047
-- Description: Detects suspicious activity where the WMIC process is used to create an autorun registry entry via reg.exe, which is often indicative of persistence mechanisms employed by malware.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%reg%' AND CommandLine ILIKE '% add %') AND (CommandLine ILIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR CommandLine ILIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR CommandLine ILIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%')) AND ((Image ILIKE '%\\wmic.exe') OR (OriginalFileName = 'wmic.exe') OR (ParentImage ILIKE '%\\wmiprvse.exe'))) AND (((CommandLine ILIKE '%:\\Perflogs%' OR CommandLine ILIKE '%:\\ProgramData'%' OR CommandLine ILIKE '%:\\Windows\\Temp%' OR CommandLine ILIKE '%:\\Temp%' OR CommandLine ILIKE '%\\AppData\\Local\\Temp%' OR CommandLine ILIKE '%\\AppData\\Roaming%' OR CommandLine ILIKE '%:\\$Recycle.bin%' OR CommandLine ILIKE '%:\\Users\\Default%' OR CommandLine ILIKE '%:\\Users\\public%' OR CommandLine ILIKE '%%temp%%' OR CommandLine ILIKE '%%tmp%%' OR CommandLine ILIKE '%%Public%%' OR CommandLine ILIKE '%%AppData%%')) OR ((CommandLine ILIKE '%:\\Users\\%') AND ((CommandLine ILIKE '%\\Favorites%' OR CommandLine ILIKE '%\\Favourites%' OR CommandLine ILIKE '%\\Contacts%' OR CommandLine ILIKE '%\\Music%' OR CommandLine ILIKE '%\\Pictures%' OR CommandLine ILIKE '%\\Documents%' OR CommandLine ILIKE '%\\Photos%')))))
