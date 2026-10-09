-- Title: Raccine Uninstall
-- ID: a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-01-21
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%taskkill %' AND CommandLine ILIKE '%RaccineSettings.exe%')) OR ((CommandLine ILIKE '%reg.exe%' AND CommandLine ILIKE '%delete%' AND CommandLine ILIKE '%Raccine Tray%')) OR ((CommandLine ILIKE '%schtasks%' AND CommandLine ILIKE '%/DELETE%' AND CommandLine ILIKE '%Raccine Rules Updater%')))
