-- Title: PowerShell Core DLL Loaded Via Office Application
-- ID: bb2ba6fb-95d4-4a25-89fc-30bb736c021a
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-06-01
-- Tags: attack.stealth
-- Description: Detects PowerShell core DLL being loaded by an Office Product
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\excel.exe' OR Image ILIKE '%\\mspub.exe' OR Image ILIKE '%\\outlook.exe' OR Image ILIKE '%\\onenote.exe' OR Image ILIKE '%\\onenoteim.exe' OR Image ILIKE '%\\powerpnt.exe' OR Image ILIKE '%\\winword.exe') AND (ImageLoaded ILIKE '%\\System.Management.Automation.Dll%' OR ImageLoaded ILIKE '%\\System.Management.Automation.ni.Dll%'))
