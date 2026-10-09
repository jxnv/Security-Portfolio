-- Title: Email Exifiltration Via Powershell
-- ID: 312d0384-401c-4b8b-abdf-685ffba9a332
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems),  Azure-Sentinel (idea)
-- Date: 2022-09-09
-- Tags: attack.exfiltration
-- Description: Detects email exfiltration via powershell cmdlets
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine LIKE '%Add-PSSnapin%' AND CommandLine LIKE '%Get-Recipient%' AND CommandLine LIKE '%-ExpandProperty%' AND CommandLine LIKE '%EmailAddresses%' AND CommandLine LIKE '%SmtpAddress%' AND CommandLine LIKE '%-hidetableheaders%'))
