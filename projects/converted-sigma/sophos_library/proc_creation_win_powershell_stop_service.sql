-- Title: Stop Windows Service Via PowerShell Stop-Service
-- ID: c49c5062-0966-4170-9efd-9968c913a6cf
-- Status: test
-- Level: low
-- Author: Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-03-05
-- Tags: attack.impact, attack.t1489
-- Description: Detects the stopping of a Windows service via the PowerShell Cmdlet "Stop-Service"
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((CommandLine ILIKE '%Stop-Service %') AND (((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll')) OR ((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe'))))
