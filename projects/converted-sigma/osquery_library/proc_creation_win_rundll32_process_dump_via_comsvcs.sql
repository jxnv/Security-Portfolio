-- Title: Process Memory Dump Via Comsvcs.DLL
-- ID: 646ea171-dded-4578-8a4d-65e9822892e3
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Modexp, Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2020-02-18
-- Tags: attack.credential-access, attack.stealth, attack.t1036, attack.t1003.001, car.2013-05-009
-- Description: Detects a process memory dump via "comsvcs.dll" using rundll32, covering multiple different techniques (ordinal, minidump function, etc.)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\rundll32.exe") OR (OriginalFileName = 'RUNDLL32.EXE') OR (CommandLine LIKE '%rundll32%')) AND ((CommandLine LIKE '%comsvcs%' AND CommandLine LIKE '%full%') AND (CommandLine LIKE '%#-%' OR CommandLine LIKE '%#+%' OR CommandLine LIKE '%#24%' OR CommandLine LIKE '%24 %' OR CommandLine LIKE '%MiniDump%' OR CommandLine LIKE '%#65560%'))) OR ((CommandLine LIKE '%24%' AND CommandLine LIKE '%comsvcs%' AND CommandLine LIKE '%full%') AND (CommandLine LIKE '% #%' OR CommandLine LIKE '%,#%' OR CommandLine LIKE '%, #%' OR CommandLine LIKE '%\"#%')))
