// Title: Potential Suspicious Windows Feature Enabled - ProcCreation
// ID: c740d4cf-a1e9-41de-bb16-8a46a4f57918
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-29
// Tags: attack.stealth
// Description: Detects usage of the built-in PowerShell cmdlet "Enable-WindowsOptionalFeature" used as a Deployment Image Servicing and Management tool.
// Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "Enable-WindowsOptionalFeature" AND CommandLine contains "-Online" AND CommandLine contains "-FeatureName")) AND ((CommandLine contains "TelnetServer" OR CommandLine contains "Internet-Explorer-Optional-amd64" OR CommandLine contains "TFTP" OR CommandLine contains "SMB1Protocol" OR CommandLine contains "Client-ProjFS" OR CommandLine contains "Microsoft-Windows-Subsystem-Linux")))
