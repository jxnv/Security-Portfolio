-- Title: Suspicious PowerShell Invocations - Specific - ProcessCreation
-- ID: 536e2947-3729-478c-9903-745aaffe60d2
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-05
-- Tags: attack.stealth
-- Description: Detects suspicious PowerShell invocation command parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%-nop%' AND CommandLine LIKE '% -w %' AND CommandLine LIKE '%hidden%' AND CommandLine LIKE '% -c %' AND CommandLine LIKE '%[Convert]::FromBase64String%')) OR ((CommandLine LIKE '% -w %' AND CommandLine LIKE '%hidden%' AND CommandLine LIKE '%-ep%' AND CommandLine LIKE '%bypass%' AND CommandLine LIKE '%-Enc%')) OR ((CommandLine LIKE '% -w %' AND CommandLine LIKE '%hidden%' AND CommandLine LIKE '%-noni%' AND CommandLine LIKE '%-nop%' AND CommandLine LIKE '% -c %' AND CommandLine LIKE '%iex%' AND CommandLine LIKE '%New-Object%')) OR ((CommandLine LIKE '%iex%' AND CommandLine LIKE '%New-Object%' AND CommandLine LIKE '%Net.WebClient%' AND CommandLine LIKE '%.Download%')) OR ((CommandLine LIKE '%powershell%' AND CommandLine LIKE '%reg%' AND CommandLine LIKE '%add%' AND CommandLine LIKE '%\\software\\%')) OR ((CommandLine LIKE '%bypass%' AND CommandLine LIKE '%-noprofile%' AND CommandLine LIKE '%-windowstyle%' AND CommandLine LIKE '%hidden%' AND CommandLine LIKE '%new-object%' AND CommandLine LIKE '%system.net.webclient%' AND CommandLine LIKE '%.download%'))) AND NOT (((CommandLine LIKE '%(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1%' OR CommandLine LIKE '%Write-ChocolateyWarning%'))))
