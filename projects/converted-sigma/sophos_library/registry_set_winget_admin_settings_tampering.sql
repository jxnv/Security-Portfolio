-- Title: Winget Admin Settings Modification
-- ID: 6db5eaf9-88f7-4ed9-af7d-9ef2ad12f236
-- Status: test
-- Level: low
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-04-17
-- Tags: attack.persistence, attack.defense-impairment
-- Description: Detects changes to the AppInstaller (winget) admin settings. Such as enabling local manifest installations or disabling installer hash checks
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%\\winget.exe' AND TargetObject ILIKE '\\REGISTRY\\A\\%' AND TargetObject ILIKE '%\\LocalState\\admin_settings')
