-- Title: Suspicious Autorun Registry Modified via WMI
-- ID: c80e66d8-1780-48a9-b412-46663fd21ac0
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-02-17
-- Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.t1547.001, attack.t1047
-- Description: Detects suspicious activity where the WMIC process is used to create an autorun registry entry via reg.exe, which is often indicative of persistence mechanisms employed by malware.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%reg%' AND CommandLine LIKE '% add %') AND (CommandLine LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR CommandLine LIKE '%\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run%' OR CommandLine LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run%')) AND ((Image="*\\wmic.exe") OR (OriginalFileName = 'wmic.exe') OR (ParentImage="*\\wmiprvse.exe"))) AND (((CommandLine LIKE '%:\\Perflogs%' OR CommandLine LIKE '%:\\ProgramData'%' OR CommandLine LIKE '%:\\Windows\\Temp%' OR CommandLine LIKE '%:\\Temp%' OR CommandLine LIKE '%\\AppData\\Local\\Temp%' OR CommandLine LIKE '%\\AppData\\Roaming%' OR CommandLine LIKE '%:\\$Recycle.bin%' OR CommandLine LIKE '%:\\Users\\Default%' OR CommandLine LIKE '%:\\Users\\public%' OR CommandLine LIKE '%%temp%%' OR CommandLine LIKE '%%tmp%%' OR CommandLine LIKE '%%Public%%' OR CommandLine LIKE '%%AppData%%')) OR ((CommandLine LIKE '%:\\Users\\%') AND ((CommandLine LIKE '%\\Favorites%' OR CommandLine LIKE '%\\Favourites%' OR CommandLine LIKE '%\\Contacts%' OR CommandLine LIKE '%\\Music%' OR CommandLine LIKE '%\\Pictures%' OR CommandLine LIKE '%\\Documents%' OR CommandLine LIKE '%\\Photos%')))))
