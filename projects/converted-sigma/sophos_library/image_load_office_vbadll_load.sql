-- Title: VBA DLL Loaded Via Office Application
-- ID: e6ce8457-68b1-485b-9bdd-3c2b5d679aa9
-- Status: test
-- Level: high
-- Author: Antonlovesdnb
-- Date: 2020-02-19
-- Tags: attack.execution, attack.t1204.002
-- Description: Detects VB DLL's loaded by an office application. Which could indicate the presence of VBA Macros.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\excel.exe' OR Image ILIKE '%\\mspub.exe' OR Image ILIKE '%\\onenote.exe' OR Image ILIKE '%\\onenoteim.exe' OR Image ILIKE '%\\outlook.exe' OR Image ILIKE '%\\powerpnt.exe' OR Image ILIKE '%\\winword.exe') AND (ImageLoaded ILIKE '%\\VBE7.DLL' OR ImageLoaded ILIKE '%\\VBEUI.DLL' OR ImageLoaded ILIKE '%\\VBE7INTL.DLL'))
