-- Title: Suspicious Volume Shadow Copy VSS_PS.dll Load
-- ID: 333cdbe8-27bb-4246-bf82-b41a0dca4b70
-- Status: test
-- Level: high
-- Author: Markus Neis, @markus_neis
-- Date: 2021-07-07
-- Tags: attack.impact, attack.t1490
-- Description: Detects the image load of vss_ps.dll by uncommon executables. This DLL is used by the Volume Shadow Copy Service (VSS) to manage shadow copies of files and volumes.
-- It is often abused by attackers to delete or manipulate shadow copies, which can hinder forensic investigations and data recovery efforts.
-- The fact that it is loaded by processes that are not typically associated with VSS operations can indicate suspicious activity.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ImageLoaded ILIKE '%\\vss_ps.dll') AND NOT (((Image IS NULL) OR (Image ILIKE 'C:\\Windows\\%' AND (Image ILIKE '%\\clussvc.exe' OR Image ILIKE '%\\dismhost.exe' OR Image ILIKE '%\\dllhost.exe' OR Image ILIKE '%\\inetsrv\\appcmd.exe' OR Image ILIKE '%\\inetsrv\\iissetup.exe' OR Image ILIKE '%\\msiexec.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\searchindexer.exe' OR Image ILIKE '%\\srtasks.exe' OR Image ILIKE '%\\svchost.exe' OR Image ILIKE '%\\System32\\SystemPropertiesAdvanced.exe' OR Image ILIKE '%\\taskhostw.exe' OR Image ILIKE '%\\thor.exe' OR Image ILIKE '%\\thor64.exe' OR Image ILIKE '%\\tiworker.exe' OR Image ILIKE '%\\vssvc.exe' OR Image ILIKE '%\\vssadmin.exe' OR Image ILIKE '%\\WmiPrvSE.exe' OR Image ILIKE '%\\wsmprovhost.exe')) OR (CommandLine ILIKE 'C:\\$WinREAgent\\Scratch\\%' AND CommandLine ILIKE '%\\dismhost.exe {%'))) AND NOT (((Image ILIKE 'C:\\Program Files\\%' OR Image ILIKE 'C:\\Program Files (x86)\\%'))))
