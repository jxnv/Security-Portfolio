-- Title: System Restore Registry Modification via CommandLine
-- ID: 7c06ab9b-b1d2-4ba9-b06e-09491ded20d9
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-03-11
-- Tags: attack.impact, attack.t1490
-- Description: Detects system restore registry modification via command line, which can be used by adversaries to disable system restore on the computer.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '% add %' OR CommandLine ILIKE '%Set-ItemProperty%' OR CommandLine ILIKE '%New-ItemProperty%')) AND ((CommandLine ILIKE '%DisableConfig%' OR CommandLine ILIKE '%DisableSR%')) AND ((CommandLine ILIKE '%\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore%' OR CommandLine ILIKE '%\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore%')) AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\reg.exe')) OR ((OriginalFileName = 'powershell.exe' OR OriginalFileName = 'pwsh.dll' OR OriginalFileName = 'reg.exe'))))
