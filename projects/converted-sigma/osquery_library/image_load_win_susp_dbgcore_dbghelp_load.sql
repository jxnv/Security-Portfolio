-- Title: Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location
-- ID: 416bc4a2-7217-4519-8dc7-c3271817f1d5
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-11-27
-- Tags: attack.credential-access, attack.defense-impairment, attack.t1003, attack.t1685
-- Description: Detects loading of dbgcore.dll or dbghelp.dll from uncommon locations such as user directories.
-- These DLLs contain the MiniDumpWriteDump function, which can be abused for credential dumping purposes or in some cases for evading EDR/AV detection by suspending processes.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ImageLoaded="*\\dbgcore.dll" OR ImageLoaded="*\\dbghelp.dll")) AND ((Image LIKE '%:\\Perflogs\\%' OR Image LIKE '%:\\Temp\\%' OR Image LIKE '%:\\Users\\Public\\%' OR Image LIKE '%\\$Recycle.Bin\\%' OR Image LIKE '%\\Contacts\\%' OR Image LIKE '%\\Documents\\%' OR Image LIKE '%\\Favorites\\%' OR Image LIKE '%\\Favourites\\%' OR Image LIKE '%\\inetpub\\wwwroot\\%' OR Image LIKE '%\\Music\\%' OR Image LIKE '%\\Pictures\\%' OR Image LIKE '%\\Start Menu\\Programs\\Startup\\%' OR Image LIKE '%\\Users\\Default\\%' OR Image LIKE '%\\Videos\\%')))
