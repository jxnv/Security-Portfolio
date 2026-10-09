-- Title: Delete Volume Shadow Copies Via WMI With PowerShell
-- ID: 87df9ee1-5416-453a-8a08-e8d4a51e9ce1
-- Status: stable
-- Level: high
-- Author: frack113
-- Date: 2021-06-03
-- Tags: attack.impact, attack.t1490
-- Description: Shadow Copies deletion using operating systems utilities via PowerShell
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Data ILIKE '%Get-WmiObject%' AND Data ILIKE '%Win32_ShadowCopy%') AND (Data ILIKE '%Delete()%' OR Data ILIKE '%Remove-WmiObject%'))
