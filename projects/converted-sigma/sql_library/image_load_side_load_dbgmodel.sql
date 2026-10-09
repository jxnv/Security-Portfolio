-- Title: Potential DLL Sideloading Of DbgModel.DLL
-- ID: fef394cd-f44d-4040-9b18-95d92fe278c0
-- Status: test
-- Level: medium
-- Author: Gary Lobermier
-- Date: 2024-07-11
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of "DbgModel.dll"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((ImageLoaded ILIKE '%\\dbgmodel.dll') AND NOT (((ImageLoaded ILIKE 'C:\\Windows\\System32\\%' OR ImageLoaded ILIKE 'C:\\Windows\\SysWOW64\\%' OR ImageLoaded ILIKE 'C:\\Windows\\WinSxS\\%'))) AND NOT (((ImageLoaded ILIKE 'C:\\Program Files\\WindowsApps\\Microsoft.WinDbg_%') OR ((ImageLoaded ILIKE 'C:\\Program Files (x86)\\Windows Kits\\%' OR ImageLoaded ILIKE 'C:\\Program Files\\Windows Kits\\%')))))
