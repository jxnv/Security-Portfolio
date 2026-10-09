-- Title: Aruba Network Service Potential DLL Sideloading
-- ID: 90ae0469-0cee-4509-b67f-e5efcef040f7
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-22
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading activity via the Aruba Networks Virtual Intranet Access "arubanetsvc.exe" process using DLL Search Order Hijacking
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\arubanetsvc.exe' AND (ImageLoaded ILIKE '%\\wtsapi32.dll' OR ImageLoaded ILIKE '%\\msvcr100.dll' OR ImageLoaded ILIKE '%\\msvcp100.dll' OR ImageLoaded ILIKE '%\\dbghelp.dll' OR ImageLoaded ILIKE '%\\dbgcore.dll' OR ImageLoaded ILIKE '%\\wininet.dll' OR ImageLoaded ILIKE '%\\iphlpapi.dll' OR ImageLoaded ILIKE '%\\version.dll' OR ImageLoaded ILIKE '%\\cryptsp.dll' OR ImageLoaded ILIKE '%\\cryptbase.dll' OR ImageLoaded ILIKE '%\\wldp.dll' OR ImageLoaded ILIKE '%\\profapi.dll' OR ImageLoaded ILIKE '%\\sspicli.dll' OR ImageLoaded ILIKE '%\\winsta.dll' OR ImageLoaded ILIKE '%\\dpapi.dll')) AND NOT (((ImageLoaded ILIKE 'C:\\Windows\\System32\\%' OR ImageLoaded ILIKE 'C:\\Windows\\SysWOW64\\%' OR ImageLoaded ILIKE 'C:\\Windows\\WinSxS\\%'))))
