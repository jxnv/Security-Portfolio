-- Title: LOL-Binary Copied From System Directory
-- ID: f5d19838-41b5-476c-98d8-ba8af4929ee2
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-29
-- Tags: attack.stealth, attack.t1036.003
-- Description: Detects a suspicious copy operation that tries to copy a known LOLBIN from system (System32, SysWOW64, WinSxS) directories to another on disk in order to bypass detections based on locations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\cmd.exe" AND CommandLine LIKE '%copy %') OR (((Image="*\\robocopy.exe" OR Image="*\\xcopy.exe")) OR ((OriginalFileName = 'robocopy.exe' OR OriginalFileName = 'XCOPY.EXE'))) OR ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '%copy-item%' OR CommandLine LIKE '% copy %' OR CommandLine LIKE '%cpi %' OR CommandLine LIKE '% cp %'))) AND (((CommandLine LIKE '%\\bitsadmin.exe%' OR CommandLine LIKE '%\\calc.exe%' OR CommandLine LIKE '%\\certutil.exe%' OR CommandLine LIKE '%\\cmdl32.exe%' OR CommandLine LIKE '%\\cscript.exe%' OR CommandLine LIKE '%\\mshta.exe%' OR CommandLine LIKE '%\\rundll32.exe%' OR CommandLine LIKE '%\\wscript.exe%' OR CommandLine LIKE '%\\ie4uinit.exe%')) AND ((CommandLine LIKE '%\\System32%' OR CommandLine LIKE '%\\SysWOW64%' OR CommandLine LIKE '%\\WinSxS%'))))
