-- Title: Usage Of Web Request Commands And Cmdlets - ScriptBlock
-- ID: 1139d2e2-84b1-4226-b445-354492eba8ba
-- Status: test
-- Level: medium
-- Author: James Pemberton / @4A616D6573
-- Date: 2019-10-24
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via PowerShell scriptblock logs
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ScriptBlockText ILIKE '%[System.Net.WebRequest]::create%' OR ScriptBlockText ILIKE '%curl %' OR ScriptBlockText ILIKE '%Invoke-RestMethod%' OR ScriptBlockText ILIKE '%Invoke-WebRequest%' OR ScriptBlockText ILIKE '% irm %' OR ScriptBlockText ILIKE '%iwr %' OR ScriptBlockText ILIKE '%Resume-BitsTransfer%' OR ScriptBlockText ILIKE '%Start-BitsTransfer%' OR ScriptBlockText ILIKE '%wget %' OR ScriptBlockText ILIKE '%WinHttp.WinHttpRequest%')) AND NOT ((Path ILIKE 'C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\%')))
