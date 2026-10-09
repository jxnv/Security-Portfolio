-- Title: Potential Suspicious Windows Feature Enabled - ProcCreation
-- ID: c740d4cf-a1e9-41de-bb16-8a46a4f57918
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-12-29
-- Tags: attack.stealth
-- Description: Detects usage of the built-in PowerShell cmdlet "Enable-WindowsOptionalFeature" used as a Deployment Image Servicing and Management tool.
-- Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%Enable-WindowsOptionalFeature%' AND CommandLine LIKE '%-Online%' AND CommandLine LIKE '%-FeatureName%')) AND ((CommandLine LIKE '%TelnetServer%' OR CommandLine LIKE '%Internet-Explorer-Optional-amd64%' OR CommandLine LIKE '%TFTP%' OR CommandLine LIKE '%SMB1Protocol%' OR CommandLine LIKE '%Client-ProjFS%' OR CommandLine LIKE '%Microsoft-Windows-Subsystem-Linux%')))
