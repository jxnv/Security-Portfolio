-- Title: Usage Of Web Request Commands And Cmdlets
-- ID: 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d
-- Status: test
-- Level: medium
-- Author: James Pemberton / @4A616D6573, Endgame, JHasenbusch, oscd.community, Austin Songer @austinsonger
-- Date: 2019-10-24
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via CommandLine
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%[System.Net.WebRequest]::create%' OR CommandLine LIKE '%curl %' OR CommandLine LIKE '%Invoke-RestMethod%' OR CommandLine LIKE '%Invoke-WebRequest%' OR CommandLine LIKE '% irm %' OR CommandLine LIKE '%iwr %' OR CommandLine LIKE '%Resume-BitsTransfer%' OR CommandLine LIKE '%Start-BitsTransfer%' OR CommandLine LIKE '%wget %' OR CommandLine LIKE '%WinHttp.WinHttpRequest%'))
