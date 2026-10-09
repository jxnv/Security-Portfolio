-- Title: Use NTFS Short Name in Command Line
-- ID: dd6b39d9-d9be-4a3b-8fe0-fe3c6a5c1795
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-05
-- Tags: attack.stealth, attack.t1564.004
-- Description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid command-line detection
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%~1.exe%' OR CommandLine LIKE '%~1.bat%' OR CommandLine LIKE '%~1.msi%' OR CommandLine LIKE '%~1.vbe%' OR CommandLine LIKE '%~1.vbs%' OR CommandLine LIKE '%~1.dll%' OR CommandLine LIKE '%~1.ps1%' OR CommandLine LIKE '%~1.js%' OR CommandLine LIKE '%~1.hta%' OR CommandLine LIKE '%~2.exe%' OR CommandLine LIKE '%~2.bat%' OR CommandLine LIKE '%~2.msi%' OR CommandLine LIKE '%~2.vbe%' OR CommandLine LIKE '%~2.vbs%' OR CommandLine LIKE '%~2.dll%' OR CommandLine LIKE '%~2.ps1%' OR CommandLine LIKE '%~2.js%' OR CommandLine LIKE '%~2.hta%')) AND NOT ((((ParentImage="*\\WebEx\\WebexHost.exe" OR ParentImage="*\\thor\\thor64.exe")) OR (CommandLine LIKE '%C:\\xampp\\vcredist\\VCREDI~1.EXE%'))))
