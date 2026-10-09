-- Title: Suspicious PowerShell Invocations - Specific - PowerShell Module
-- ID: 8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro
-- Date: 2017-03-05
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects suspicious PowerShell invocation command parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((ContextInfo ILIKE '%-nop%' AND ContextInfo ILIKE '% -w %' AND ContextInfo ILIKE '%hidden%' AND ContextInfo ILIKE '% -c %' AND ContextInfo ILIKE '%[Convert]::FromBase64String%')) OR ((ContextInfo ILIKE '% -w %' AND ContextInfo ILIKE '%hidden%' AND ContextInfo ILIKE '%-ep%' AND ContextInfo ILIKE '%bypass%' AND ContextInfo ILIKE '%-Enc%')) OR ((ContextInfo ILIKE '% -w %' AND ContextInfo ILIKE '%hidden%' AND ContextInfo ILIKE '%-noni%' AND ContextInfo ILIKE '%-nop%' AND ContextInfo ILIKE '% -c %' AND ContextInfo ILIKE '%iex%' AND ContextInfo ILIKE '%New-Object%')) OR ((ContextInfo ILIKE '%iex%' AND ContextInfo ILIKE '%New-Object%' AND ContextInfo ILIKE '%Net.WebClient%' AND ContextInfo ILIKE '%.Download%')) OR ((ContextInfo ILIKE '%powershell%' AND ContextInfo ILIKE '%reg%' AND ContextInfo ILIKE '%add%') AND (ContextInfo ILIKE '%\\software\\microsoft\\windows\\currentversion\\run%' OR ContextInfo ILIKE '%\\software\\wow6432node\\microsoft\\windows\\currentversion\\run%' OR ContextInfo ILIKE '%\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run%')) OR ((ContextInfo ILIKE '%bypass%' AND ContextInfo ILIKE '%-noprofile%' AND ContextInfo ILIKE '%-windowstyle%' AND ContextInfo ILIKE '%hidden%' AND ContextInfo ILIKE '%new-object%' AND ContextInfo ILIKE '%system.net.webclient%' AND ContextInfo ILIKE '%.download%'))) AND NOT (((ContextInfo ILIKE '%(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1%' OR ContextInfo ILIKE '%Write-ChocolateyWarning%'))))
