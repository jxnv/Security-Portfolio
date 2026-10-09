-- Title: Potential Encoded PowerShell Patterns In CommandLine
-- ID: cdf05894-89e7-4ead-b2b0-0a5f97a90f2f
-- Status: test
-- Level: low
-- Author: Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton
-- Date: 2020-10-11
-- Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
-- Description: Detects specific combinations of encoding methods in PowerShell via the commandline
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((Image="*\\powershell.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((((CommandLine LIKE '%ToInt%' OR CommandLine LIKE '%ToDecimal%' OR CommandLine LIKE '%ToByte%' OR CommandLine LIKE '%ToUint%' OR CommandLine LIKE '%ToSingle%' OR CommandLine LIKE '%ToSByte%')) AND ((CommandLine LIKE '%ToChar%' OR CommandLine LIKE '%ToString%' OR CommandLine LIKE '%String%'))) OR (((CommandLine LIKE '%char%' AND CommandLine LIKE '%join%')) OR ((CommandLine LIKE '%split%' AND CommandLine LIKE '%join%')))))
