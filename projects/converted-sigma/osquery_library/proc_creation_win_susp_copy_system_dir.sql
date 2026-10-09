-- Title: Suspicious Copy From or To System Directory
-- ID: fff9d2b7-e11c-4a69-93d3-40ef66189767
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Markus Neis, Tim Shelton (HAWK.IO), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2020-07-03
-- Tags: attack.stealth, attack.t1036.003
-- Description: Detects a suspicious copy operation that tries to copy a program from system (System32, SysWOW64, WinSxS) directories to another on disk.
-- Often used to move LOLBINs such as 'certutil' or 'desktopimgdownldr' to a different location with a different name in order to bypass detections based on locations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\cmd.exe" AND CommandLine LIKE '%copy %') OR (((Image="*\\robocopy.exe" OR Image="*\\xcopy.exe")) OR ((OriginalFileName = 'robocopy.exe' OR OriginalFileName = 'XCOPY.EXE'))) OR ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '%copy-item%' OR CommandLine LIKE '% copy %' OR CommandLine LIKE '%cpi %' OR CommandLine LIKE '% cp %'))) AND (CommandLine=regex("\\s['\"]?C:\\\\Windows\\\\(?:System32|SysWOW64|WinSxS)")) AND NOT ((Image="*\\cmd.exe" AND (CommandLine LIKE '%/c copy%' AND CommandLine LIKE '%\\Temp\\%' AND CommandLine LIKE '%\\avira_system_speedup.exe%') AND (CommandLine LIKE '%C:\\Program Files\\Avira\\%' OR CommandLine LIKE '%C:\\Program Files (x86)\\Avira\\%'))))
