-- Title: Code Execution via Pcwutl.dll
-- ID: 9386d78a-7207-4048-9c9f-a93a7c2d1c05
-- Status: test
-- Level: medium
-- Author: Julia Fomina, oscd.community
-- Date: 2020-10-05
-- Tags: attack.stealth, attack.t1218.011
-- Description: Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%pcwutl%' AND CommandLine ILIKE '%LaunchApplication%')) AND ((Image ILIKE '%\\rundll32.exe') OR (OriginalFileName = 'RUNDLL32.EXE')))
