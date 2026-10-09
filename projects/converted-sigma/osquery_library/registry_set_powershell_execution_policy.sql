-- Title: Potential PowerShell Execution Policy Tampering
-- ID: fad91067-08c5-4d1a-8d8c-d96a21b37814
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-11
-- Tags: attack.defense-impairment
-- Description: Detects changes to the PowerShell execution policy in order to bypass signing requirements for script execution
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetObject="*\\ShellIds\\Microsoft.PowerShell\\ExecutionPolicy" OR TargetObject="*\\Policies\\Microsoft\\Windows\\PowerShell\\ExecutionPolicy") AND (Details LIKE '%Bypass%' OR Details LIKE '%Unrestricted%')) AND NOT (((Image LIKE '%:\\Windows\\System32\\%' OR Image LIKE '%:\\Windows\\SysWOW64\\%'))))
