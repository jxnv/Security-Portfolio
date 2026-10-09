-- Title: Suspicious PowerShell Invocations - Specific - ProcessCreation
-- ID: 536e2947-3729-478c-9903-745aaffe60d2
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-05
-- Tags: attack.stealth
-- Description: Detects suspicious PowerShell invocation command parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((CommandLine ILIKE '%-nop%' AND CommandLine ILIKE '% -w %' AND CommandLine ILIKE '%hidden%' AND CommandLine ILIKE '% -c %' AND CommandLine ILIKE '%[Convert]::FromBase64String%')) OR ((CommandLine ILIKE '% -w %' AND CommandLine ILIKE '%hidden%' AND CommandLine ILIKE '%-ep%' AND CommandLine ILIKE '%bypass%' AND CommandLine ILIKE '%-Enc%')) OR ((CommandLine ILIKE '% -w %' AND CommandLine ILIKE '%hidden%' AND CommandLine ILIKE '%-noni%' AND CommandLine ILIKE '%-nop%' AND CommandLine ILIKE '% -c %' AND CommandLine ILIKE '%iex%' AND CommandLine ILIKE '%New-Object%')) OR ((CommandLine ILIKE '%iex%' AND CommandLine ILIKE '%New-Object%' AND CommandLine ILIKE '%Net.WebClient%' AND CommandLine ILIKE '%.Download%')) OR ((CommandLine ILIKE '%powershell%' AND CommandLine ILIKE '%reg%' AND CommandLine ILIKE '%add%' AND CommandLine ILIKE '%\\software\\%')) OR ((CommandLine ILIKE '%bypass%' AND CommandLine ILIKE '%-noprofile%' AND CommandLine ILIKE '%-windowstyle%' AND CommandLine ILIKE '%hidden%' AND CommandLine ILIKE '%new-object%' AND CommandLine ILIKE '%system.net.webclient%' AND CommandLine ILIKE '%.download%'))) AND NOT (((CommandLine ILIKE '%(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1%' OR CommandLine ILIKE '%Write-ChocolateyWarning%'))))
