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

SELECT * FROM security_logs WHERE (((ImageLoaded ILIKE '%\\dbgcore.dll' OR ImageLoaded ILIKE '%\\dbghelp.dll')) AND ((Image ILIKE '%:\\Perflogs\\%' OR Image ILIKE '%:\\Temp\\%' OR Image ILIKE '%:\\Users\\Public\\%' OR Image ILIKE '%\\$Recycle.Bin\\%' OR Image ILIKE '%\\Contacts\\%' OR Image ILIKE '%\\Documents\\%' OR Image ILIKE '%\\Favorites\\%' OR Image ILIKE '%\\Favourites\\%' OR Image ILIKE '%\\inetpub\\wwwroot\\%' OR Image ILIKE '%\\Music\\%' OR Image ILIKE '%\\Pictures\\%' OR Image ILIKE '%\\Start Menu\\Programs\\Startup\\%' OR Image ILIKE '%\\Users\\Default\\%' OR Image ILIKE '%\\Videos\\%')))
