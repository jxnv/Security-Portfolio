-- Title: LOL-Binary Copied From System Directory
-- ID: f5d19838-41b5-476c-98d8-ba8af4929ee2
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-29
-- Tags: attack.stealth, attack.t1036.003
-- Description: Detects a suspicious copy operation that tries to copy a known LOLBIN from system (System32, SysWOW64, WinSxS) directories to another on disk in order to bypass detections based on locations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\cmd.exe' AND CommandLine ILIKE '%copy %') OR (((Image ILIKE '%\\robocopy.exe' OR Image ILIKE '%\\xcopy.exe')) OR ((OriginalFileName = 'robocopy.exe' OR OriginalFileName = 'XCOPY.EXE'))) OR ((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe') AND (CommandLine ILIKE '%copy-item%' OR CommandLine ILIKE '% copy %' OR CommandLine ILIKE '%cpi %' OR CommandLine ILIKE '% cp %'))) AND (((CommandLine ILIKE '%\\bitsadmin.exe%' OR CommandLine ILIKE '%\\calc.exe%' OR CommandLine ILIKE '%\\certutil.exe%' OR CommandLine ILIKE '%\\cmdl32.exe%' OR CommandLine ILIKE '%\\cscript.exe%' OR CommandLine ILIKE '%\\mshta.exe%' OR CommandLine ILIKE '%\\rundll32.exe%' OR CommandLine ILIKE '%\\wscript.exe%' OR CommandLine ILIKE '%\\ie4uinit.exe%')) AND ((CommandLine ILIKE '%\\System32%' OR CommandLine ILIKE '%\\SysWOW64%' OR CommandLine ILIKE '%\\WinSxS%'))))
