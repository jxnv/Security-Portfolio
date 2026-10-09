-- Title: Potential PowerShell Execution Policy Tampering
-- ID: fad91067-08c5-4d1a-8d8c-d96a21b37814
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-11
-- Tags: attack.defense-impairment
-- Description: Detects changes to the PowerShell execution policy in order to bypass signing requirements for script execution
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((TargetObject ILIKE '%\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy' OR TargetObject ILIKE '%\\Policies\\Microsoft\\Windows\\PowerShell\\ExecutionPolicy') AND (Details ILIKE '%Bypass%' OR Details ILIKE '%Unrestricted%')) AND NOT (((Image ILIKE '%:\\Windows\\System32\\%' OR Image ILIKE '%:\\Windows\\SysWOW64\\%'))))
