-- Title: Windows EventLog Autologger Session Registry Modification Via CommandLine
-- ID: d7b81144-b866-48a4-9bcc-275dc69d870e
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-12-25
-- Tags: attack.defense-impairment, attack.t1685.001
-- Description: Detects attempts to disable Windows EventLog autologger sessions via registry modification.
-- The AutoLogger event tracing session records events that occur early in the operating system boot process.
-- Applications and device drivers can use the AutoLogger session to capture traces before the user logs in.
-- Adversaries may disable these sessions to evade detection and prevent security monitoring of early boot activities and system events.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%add %' OR CommandLine ILIKE '%Set-ItemProperty%' OR CommandLine ILIKE '%New-ItemProperty%' OR CommandLine ILIKE '%si %')) AND (CommandLine ILIKE '%\\Control\\WMI\\Autologger\\%') AND ((CommandLine ILIKE '%Start%' OR CommandLine ILIKE '%Enabled%')) AND (((Image ILIKE '%\\reg.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'reg.exe' OR OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
