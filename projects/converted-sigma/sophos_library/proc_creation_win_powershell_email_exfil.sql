-- Title: Email Exifiltration Via Powershell
-- ID: 312d0384-401c-4b8b-abdf-685ffba9a332
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems),  Azure-Sentinel (idea)
-- Date: 2022-09-09
-- Tags: attack.exfiltration
-- Description: Detects email exfiltration via powershell cmdlets
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe') AND (CommandLine ILIKE '%Add-PSSnapin%' AND CommandLine ILIKE '%Get-Recipient%' AND CommandLine ILIKE '%-ExpandProperty%' AND CommandLine ILIKE '%EmailAddresses%' AND CommandLine ILIKE '%SmtpAddress%' AND CommandLine ILIKE '%-hidetableheaders%'))
