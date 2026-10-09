-- Title: Suspicious PowerShell Invocations - Specific - PowerShell Module
-- ID: 8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro
-- Date: 2017-03-05
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects suspicious PowerShell invocation command parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((((ContextInfo LIKE '%-nop%' AND ContextInfo LIKE '% -w %' AND ContextInfo LIKE '%hidden%' AND ContextInfo LIKE '% -c %' AND ContextInfo LIKE '%[Convert]::FromBase64String%')) OR ((ContextInfo LIKE '% -w %' AND ContextInfo LIKE '%hidden%' AND ContextInfo LIKE '%-ep%' AND ContextInfo LIKE '%bypass%' AND ContextInfo LIKE '%-Enc%')) OR ((ContextInfo LIKE '% -w %' AND ContextInfo LIKE '%hidden%' AND ContextInfo LIKE '%-noni%' AND ContextInfo LIKE '%-nop%' AND ContextInfo LIKE '% -c %' AND ContextInfo LIKE '%iex%' AND ContextInfo LIKE '%New-Object%')) OR ((ContextInfo LIKE '%iex%' AND ContextInfo LIKE '%New-Object%' AND ContextInfo LIKE '%Net.WebClient%' AND ContextInfo LIKE '%.Download%')) OR ((ContextInfo LIKE '%powershell%' AND ContextInfo LIKE '%reg%' AND ContextInfo LIKE '%add%') AND (ContextInfo LIKE '%\\software\\microsoft\\windows\\currentversion\\run%' OR ContextInfo LIKE '%\\software\\wow6432node\\microsoft\\windows\\currentversion\\run%' OR ContextInfo LIKE '%\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run%')) OR ((ContextInfo LIKE '%bypass%' AND ContextInfo LIKE '%-noprofile%' AND ContextInfo LIKE '%-windowstyle%' AND ContextInfo LIKE '%hidden%' AND ContextInfo LIKE '%new-object%' AND ContextInfo LIKE '%system.net.webclient%' AND ContextInfo LIKE '%.download%'))) AND NOT (((ContextInfo LIKE '%(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1%' OR ContextInfo LIKE '%Write-ChocolateyWarning%'))))
