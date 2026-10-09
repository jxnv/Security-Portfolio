-- Title: DotNET Assembly DLL Loaded Via Office Application
-- ID: ff0f2b05-09db-4095-b96d-1b75ca24894a
-- Status: test
-- Level: medium
-- Author: Antonlovesdnb
-- Date: 2020-02-19
-- Tags: attack.execution, attack.t1204.002
-- Description: Detects any assembly DLL being loaded by an Office Product
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Image ILIKE '%\\excel.exe' OR Image ILIKE '%\\mspub.exe' OR Image ILIKE '%\\onenote.exe' OR Image ILIKE '%\\onenoteim.exe' OR Image ILIKE '%\\outlook.exe' OR Image ILIKE '%\\powerpnt.exe' OR Image ILIKE '%\\winword.exe') AND ImageLoaded ILIKE 'C:\\Windows\\assembly\\%')
