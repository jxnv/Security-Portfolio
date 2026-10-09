-- Title: Usage Of Web Request Commands And Cmdlets
-- ID: 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d
-- Status: test
-- Level: medium
-- Author: James Pemberton / @4A616D6573, Endgame, JHasenbusch, oscd.community, Austin Songer @austinsonger
-- Date: 2019-10-24
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via CommandLine
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%[System.Net.WebRequest]::create%' OR CommandLine ILIKE '%curl %' OR CommandLine ILIKE '%Invoke-RestMethod%' OR CommandLine ILIKE '%Invoke-WebRequest%' OR CommandLine ILIKE '% irm %' OR CommandLine ILIKE '%iwr %' OR CommandLine ILIKE '%Resume-BitsTransfer%' OR CommandLine ILIKE '%Start-BitsTransfer%' OR CommandLine ILIKE '%wget %' OR CommandLine ILIKE '%WinHttp.WinHttpRequest%'))
