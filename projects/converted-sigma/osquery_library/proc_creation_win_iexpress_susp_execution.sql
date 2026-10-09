-- Title: Self Extracting Package Creation Via Iexpress.EXE From Potentially Suspicious Location
-- ID: b2b048b0-7857-4380-b0fb-d3f0ab820b71
-- Status: test
-- Level: high
-- Author: Joseliyo Sanchez, @Joseliyo_Jstnk, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2024-02-05
-- Tags: attack.stealth, attack.t1218
-- Description: Detects the use of iexpress.exe to create binaries via Self Extraction Directive (SED) files located in potentially suspicious locations.
-- This behavior has been observed in-the-wild by different threat actors.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '% /n %') AND ((Image="*\\iexpress.exe") OR (OriginalFileName = 'IEXPRESS.exe')) AND ((CommandLine LIKE '%:\\ProgramData\\%' OR CommandLine LIKE '%:\\Temp\\%' OR CommandLine LIKE '%:\\Windows\\System32\\Tasks\\%' OR CommandLine LIKE '%:\\Windows\\Tasks\\%' OR CommandLine LIKE '%:\\Windows\\Temp\\%' OR CommandLine LIKE '%\\AppData\\Local\\Temp\\%')))
