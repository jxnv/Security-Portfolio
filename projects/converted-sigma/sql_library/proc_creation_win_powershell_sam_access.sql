-- Title: PowerShell SAM Copy
-- ID: 1af57a4b-460a-4738-9034-db68b880c665
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-07-29
-- Tags: attack.credential-access, attack.t1003.002
-- Description: Detects suspicious PowerShell scripts accessing SAM hives
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%\\HarddiskVolumeShadowCopy%' AND CommandLine ILIKE '%System32\\config\\sam%')) AND ((CommandLine ILIKE '%Copy-Item%' OR CommandLine ILIKE '%cp $_.%' OR CommandLine ILIKE '%cpi $_.%' OR CommandLine ILIKE '%copy $_.%' OR CommandLine ILIKE '%.File]::Copy(%')))
