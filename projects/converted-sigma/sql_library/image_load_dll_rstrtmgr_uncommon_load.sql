-- Title: Load Of RstrtMgr.DLL By An Uncommon Process
-- ID: 3669afd2-9891-4534-a626-e5cf03810a61
-- Status: test
-- Level: low
-- Author: Luc Génaux
-- Date: 2023-11-28
-- Tags: attack.impact, attack.defense-impairment, attack.t1486, attack.t1685
-- Description: Detects the load of RstrtMgr DLL (Restart Manager) by an uncommon process.
-- This library has been used during ransomware campaigns to kill processes that would prevent file encryption by locking them (e.g. Conti ransomware, Cactus ransomware). It has also recently been seen used by the BiBi wiper for Windows.
-- It could also be used for anti-analysis purposes by shut downing specific processes.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ImageLoaded ILIKE '%\\RstrtMgr.dll') OR (OriginalFileName = 'RstrtMgr.dll')) AND NOT (((Image ILIKE 'C:\\Windows\\Temp\\%') OR ((Image ILIKE 'C:\\$WINDOWS.~BT\\%' OR Image ILIKE 'C:\\$WinREAgent\\%' OR Image ILIKE 'C:\\Program Files (x86)\\%' OR Image ILIKE 'C:\\Program Files\\%' OR Image ILIKE 'C:\\ProgramData\\%' OR Image ILIKE 'C:\\Windows\\explorer.exe%' OR Image ILIKE 'C:\\Windows\\SoftwareDistribution\\%' OR Image ILIKE 'C:\\Windows\\SysNative\\%' OR Image ILIKE 'C:\\Windows\\System32\\%' OR Image ILIKE 'C:\\Windows\\SysWOW64\\%' OR Image ILIKE 'C:\\Windows\\WinSxS\\%' OR Image ILIKE 'C:\\WUDownloadCache\\%')) OR (Image ILIKE 'C:\\Users\\%' AND (Image ILIKE '%\\AppData\\Local\\Temp\\is-%' AND Image ILIKE '%.tmp\\%') AND Image ILIKE '%.tmp'))) AND NOT (((Image ILIKE 'C:\\Users\\%' AND (Image ILIKE '%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe' OR Image ILIKE '%\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe')) OR (Image ILIKE 'C:\\Users\\%' AND Image ILIKE '%\\AppData\\Local\\Microsoft\\OneDrive\\%' AND Image ILIKE '%\\OneDrive.Sync.Service.exe'))))
