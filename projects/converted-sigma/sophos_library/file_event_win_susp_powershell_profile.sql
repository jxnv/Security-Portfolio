-- Title: PowerShell Profile Modification
-- ID: b5b78988-486d-4a80-b991-930eff3ff8bf
-- Status: test
-- Level: medium
-- Author: HieuTT35, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2019-10-24
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1546.013
-- Description: Detects the creation or modification of a powershell profile which could indicate suspicious activity as the profile can be used as a mean of persistence
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((TargetFilename ILIKE '%\\Microsoft.PowerShell_profile.ps1' OR TargetFilename ILIKE '%\\PowerShell\\profile.ps1' OR TargetFilename ILIKE '%\\Program Files\\PowerShell\\7-preview\\profile.ps1' OR TargetFilename ILIKE '%\\Program Files\\PowerShell\\7\\profile.ps1' OR TargetFilename ILIKE '%\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.ps1' OR TargetFilename ILIKE '%\\WindowsPowerShell\\profile.ps1'))
