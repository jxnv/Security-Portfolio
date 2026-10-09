-- Title: Suspicious Service DACL Modification Via Set-Service Cmdlet
-- ID: a95b9b42-1308-4735-a1af-abb1c5e6f5ac
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-18
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1543.003
-- Description: Detects suspicious DACL modifications via the "Set-Service" cmdlet using the "SecurityDescriptorSddl" flag (Only available with PowerShell 7) that can be used to hide services or make them unstopable
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\pwsh.exe") OR (OriginalFileName = 'pwsh.dll')) AND ((CommandLine LIKE '%-SecurityDescriptorSddl %' OR CommandLine LIKE '%-sd %')) AND ((CommandLine LIKE '%Set-Service %' AND CommandLine LIKE '%D;;%') AND (CommandLine LIKE '%;;;IU%' OR CommandLine LIKE '%;;;SU%' OR CommandLine LIKE '%;;;BA%' OR CommandLine LIKE '%;;;SY%' OR CommandLine LIKE '%;;;WD%')))
