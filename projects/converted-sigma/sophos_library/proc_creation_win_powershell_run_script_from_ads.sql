-- Title: Run PowerShell Script from ADS
-- ID: 45a594aa-1fbd-4972-a809-ff5a99dd81b8
-- Status: test
-- Level: high
-- Author: Sergey Soldatov, Kaspersky Lab, oscd.community
-- Date: 2019-10-30
-- Tags: attack.stealth, attack.t1564.004
-- Description: Detects PowerShell script execution from Alternate Data Stream (ADS)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\powershell.exe' OR ParentImage ILIKE '%\\pwsh.exe') AND (Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe') AND (CommandLine ILIKE '%Get-Content%' AND CommandLine ILIKE '%-Stream%'))
