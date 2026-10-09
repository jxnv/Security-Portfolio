-- Title: Deletion of Volume Shadow Copies via WMI with PowerShell
-- ID: 21ff4ca9-f13a-41ad-b828-0077b2af2e40
-- Status: test
-- Level: high
-- Author: Tim Rauch, Elastic (idea)
-- Date: 2022-09-20
-- Tags: attack.impact, attack.t1490
-- Description: Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.Delete()%' OR CommandLine LIKE '%Remove-WmiObject%' OR CommandLine LIKE '%rwmi%' OR CommandLine LIKE '%Remove-CimInstance%' OR CommandLine LIKE '%rcim%')) AND ((CommandLine LIKE '%Get-WmiObject%' OR CommandLine LIKE '%gwmi%' OR CommandLine LIKE '%Get-CimInstance%' OR CommandLine LIKE '%gcim%')) AND (CommandLine LIKE '%Win32_ShadowCopy%'))
