-- Title: PowerShell SAM Copy
-- ID: 1af57a4b-460a-4738-9034-db68b880c665
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-07-29
-- Tags: attack.credential-access, attack.t1003.002
-- Description: Detects suspicious PowerShell scripts accessing SAM hives
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%\\HarddiskVolumeShadowCopy%' AND CommandLine LIKE '%System32\\config\\sam%')) AND ((CommandLine LIKE '%Copy-Item%' OR CommandLine LIKE '%cp $_.%' OR CommandLine LIKE '%cpi $_.%' OR CommandLine LIKE '%copy $_.%' OR CommandLine LIKE '%.File]::Copy(%')))
