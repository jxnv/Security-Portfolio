-- Title: PowerShell Get-Process LSASS
-- ID: b2815d0d-7481-4bf0-9b6c-a4c48a94b349
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-04-23
-- Tags: attack.credential-access, attack.t1552.004
-- Description: Detects a "Get-Process" cmdlet and it's aliases on lsass process, which is in almost all cases a sign of malicious activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%Get-Process lsas%' OR CommandLine ILIKE '%ps lsas%' OR CommandLine ILIKE '%gps lsas%'))
