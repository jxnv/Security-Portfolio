-- Title: ScreenSaver Registry Key Set
-- ID: 40b6e656-4e11-4c0c-8772-c1cc6dae34ce
-- Status: test
-- Level: medium
-- Author: Jose Luis Sanchez Martinez (@Joseliyo_Jstnk)
-- Date: 2022-05-04
-- Tags: attack.stealth, attack.t1218.011
-- Description: Detects registry key established after masqueraded .scr file execution using Rundll32 through desk.cpl
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\rundll32.exe') AND (TargetObject ILIKE '%\\Control Panel\\Desktop\\SCRNSAVE.EXE%' AND Details ILIKE '%.scr') AND NOT (((Details ILIKE '%C:\\Windows\\System32\\%' OR Details ILIKE '%C:\\Windows\\SysWOW64\\%'))))
