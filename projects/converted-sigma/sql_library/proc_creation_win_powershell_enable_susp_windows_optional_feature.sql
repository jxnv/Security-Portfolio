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

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%Enable-WindowsOptionalFeature%' AND CommandLine ILIKE '%-Online%' AND CommandLine ILIKE '%-FeatureName%')) AND ((CommandLine ILIKE '%TelnetServer%' OR CommandLine ILIKE '%Internet-Explorer-Optional-amd64%' OR CommandLine ILIKE '%TFTP%' OR CommandLine ILIKE '%SMB1Protocol%' OR CommandLine ILIKE '%Client-ProjFS%' OR CommandLine ILIKE '%Microsoft-Windows-Subsystem-Linux%')))
