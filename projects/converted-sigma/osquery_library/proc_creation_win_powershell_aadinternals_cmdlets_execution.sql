-- Title: AADInternals PowerShell Cmdlets Execution - ProccessCreation
-- ID: c86500e9-a645-4680-98d7-f882c70c1ea3
-- Status: test
-- Level: high
-- Author: Austin Songer (@austinsonger), Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2022-12-23
-- Tags: attack.execution, attack.reconnaissance, attack.discovery, attack.credential-access, attack.impact
-- Description: Detects ADDInternals Cmdlet execution. A tool for administering Azure AD and Office 365. Which can be abused by threat actors to attack Azure AD or Office 365.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Add-AADInt%' OR CommandLine LIKE '%ConvertTo-AADInt%' OR CommandLine LIKE '%Disable-AADInt%' OR CommandLine LIKE '%Enable-AADInt%' OR CommandLine LIKE '%Export-AADInt%' OR CommandLine LIKE '%Find-AADInt%' OR CommandLine LIKE '%Get-AADInt%' OR CommandLine LIKE '%Grant-AADInt%' OR CommandLine LIKE '%Initialize-AADInt%' OR CommandLine LIKE '%Install-AADInt%' OR CommandLine LIKE '%Invoke-AADInt%' OR CommandLine LIKE '%Join-AADInt%' OR CommandLine LIKE '%New-AADInt%' OR CommandLine LIKE '%Open-AADInt%' OR CommandLine LIKE '%Read-AADInt%' OR CommandLine LIKE '%Register-AADInt%' OR CommandLine LIKE '%Remove-AADInt%' OR CommandLine LIKE '%Reset-AADInt%' OR CommandLine LIKE '%Resolve-AADInt%' OR CommandLine LIKE '%Restore-AADInt%' OR CommandLine LIKE '%Save-AADInt%' OR CommandLine LIKE '%Search-AADInt%' OR CommandLine LIKE '%Send-AADInt%' OR CommandLine LIKE '%Set-AADInt%' OR CommandLine LIKE '%Start-AADInt%' OR CommandLine LIKE '%Unprotect-AADInt%' OR CommandLine LIKE '%Update-AADInt%')) AND (((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe")) OR ((OriginalFileName = 'PowerShell.Exe' OR OriginalFileName = 'pwsh.dll'))))
