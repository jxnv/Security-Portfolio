-- Title: Clear PowerShell History - PowerShell Module
-- ID: f99276ad-d122-4989-a09a-d00904a5f9d2
-- Status: test
-- Level: medium
-- Author: Ilyas Ochkov, Jonhnathan Ribeiro, Daniil Yugoslavskiy, oscd.community
-- Date: 2019-10-25
-- Tags: attack.stealth, attack.t1070.003
-- Description: Detects keywords that could indicate clearing PowerShell history
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((Payload ILIKE '%Set-PSReadlineOption%' AND Payload ILIKE '%–HistorySaveStyle%' AND Payload ILIKE '%SaveNothing%')) OR ((Payload ILIKE '%Set-PSReadlineOption%' AND Payload ILIKE '%-HistorySaveStyle%' AND Payload ILIKE '%SaveNothing%'))) OR (((Payload ILIKE '%del%' OR Payload ILIKE '%Remove-Item%' OR Payload ILIKE '%rm%')) AND (Payload ILIKE '%(Get-PSReadlineOption).HistorySavePath%')))
