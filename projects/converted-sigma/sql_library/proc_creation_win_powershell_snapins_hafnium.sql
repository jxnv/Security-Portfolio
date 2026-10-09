-- Title: Exchange PowerShell Snap-Ins Usage
-- ID: 25676e10-2121-446e-80a4-71ff8506af47
-- Status: test
-- Level: high
-- Author: FPT.EagleEye, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-03-03
-- Tags: attack.execution, attack.t1059.001, attack.collection, attack.t1114
-- Description: Detects adding and using Exchange PowerShell snap-ins to export mailbox data. As seen used by HAFNIUM and APT27
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%Add-PSSnapin%') AND (((Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe')) OR ((OriginalFileName = 'PowerShell.EXE' OR OriginalFileName = 'pwsh.dll'))) AND ((CommandLine ILIKE '%Microsoft.Exchange.Powershell.Snapin%' OR CommandLine ILIKE '%Microsoft.Exchange.Management.PowerShell.SnapIn%'))) AND NOT ((ParentImage = 'C:\\Windows\\System32\\msiexec.exe' AND CommandLine ILIKE '%$exserver=Get-ExchangeServer ([Environment]::MachineName) -ErrorVariable exerr 2> $null%')))
