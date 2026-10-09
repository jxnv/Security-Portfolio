-- Title: Copy From Or To Admin Share Or Sysvol Folder
-- ID: 855bc8b5-2ae8-402e-a9ed-b889e6df1900
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, Nasreddine Bencherchali
-- Date: 2019-12-30
-- Tags: attack.lateral-movement, attack.collection, attack.exfiltration, attack.t1039, attack.t1048, attack.t1021.002
-- Description: Detects a copy command or a copy utility execution to or from an Admin share or remote
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%\\\\\\\\*\\\\*$%' OR CommandLine LIKE '%\\Sysvol\\%')) AND ((((Image="*\\robocopy.exe" OR Image="*\\xcopy.exe")) OR ((OriginalFileName = 'robocopy.exe' OR OriginalFileName = 'XCOPY.EXE'))) OR ((CommandLine LIKE '%copy%') AND ((Image="*\\cmd.exe") OR (OriginalFileName = 'Cmd.Exe'))) OR (((CommandLine LIKE '%copy-item%' OR CommandLine LIKE '%copy %' OR CommandLine LIKE '%cpi %' OR CommandLine LIKE '% cp %' OR CommandLine LIKE '%move %' OR CommandLine LIKE '% move-item%' OR CommandLine LIKE '% mi %' OR CommandLine LIKE '% mv %')) AND (((Image LIKE '%\\powershell_ise.exe%' OR Image LIKE '%\\powershell.exe%' OR Image LIKE '%\\pwsh.exe%')) OR ((OriginalFileName = 'powershell_ise.exe' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))))
