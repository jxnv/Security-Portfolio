-- Title: Add Windows Capability Via PowerShell Cmdlet
-- ID: b36d01a3-ddaf-4804-be18-18a6247adfcd
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-22
-- Tags: attack.execution
-- Description: Detects usage of the "Add-WindowsCapability" cmdlet to add Windows capabilities. Notable capabilities could be "OpenSSH" and others.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((CommandLine ILIKE '%OpenSSH.%') AND (CommandLine ILIKE '%Add-WindowsCapability%') AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))))
