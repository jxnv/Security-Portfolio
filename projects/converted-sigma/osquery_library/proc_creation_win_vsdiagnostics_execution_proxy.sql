-- Title: Potential Binary Proxy Execution Via VSDiagnostics.EXE
-- ID: ac1c92b4-ac81-405a-9978-4604d78cc47e
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-08-03
-- Tags: attack.stealth, attack.t1218
-- Description: Detects execution of "VSDiagnostics.exe" with the "start" command in order to launch and proxy arbitrary binaries.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% /launch:%' OR CommandLine LIKE '% -launch:%')) AND (CommandLine LIKE '%start%') AND ((Image="*\\VSDiagnostics.exe") OR (OriginalFileName = 'VSDiagnostics.exe')))
