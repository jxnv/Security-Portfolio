-- Title: Usage Of Web Request Commands And Cmdlets - ScriptBlock
-- ID: 1139d2e2-84b1-4226-b445-354492eba8ba
-- Status: test
-- Level: medium
-- Author: James Pemberton / @4A616D6573
-- Date: 2019-10-24
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via PowerShell scriptblock logs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ScriptBlockText LIKE '%[System.Net.WebRequest]::create%' OR ScriptBlockText LIKE '%curl %' OR ScriptBlockText LIKE '%Invoke-RestMethod%' OR ScriptBlockText LIKE '%Invoke-WebRequest%' OR ScriptBlockText LIKE '% irm %' OR ScriptBlockText LIKE '%iwr %' OR ScriptBlockText LIKE '%Resume-BitsTransfer%' OR ScriptBlockText LIKE '%Start-BitsTransfer%' OR ScriptBlockText LIKE '%wget %' OR ScriptBlockText LIKE '%WinHttp.WinHttpRequest%')) AND NOT ((Path="C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\*")))
