-- Title: CLR DLL Loaded Via Office Applications
-- ID: d13c43f0-f66b-4279-8b2c-5912077c1780
-- Status: test
-- Level: medium
-- Author: Antonlovesdnb
-- Date: 2020-02-19
-- Tags: attack.execution, attack.t1204.002
-- Description: Detects CLR DLL being loaded by an Office Product
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\excel.exe' OR Image ILIKE '%\\mspub.exe' OR Image ILIKE '%\\outlook.exe' OR Image ILIKE '%\\onenote.exe' OR Image ILIKE '%\\onenoteim.exe' OR Image ILIKE '%\\powerpnt.exe' OR Image ILIKE '%\\winword.exe') AND ImageLoaded ILIKE '%\\clr.dll%')
