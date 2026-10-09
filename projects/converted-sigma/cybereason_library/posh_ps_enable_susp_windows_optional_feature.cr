// Title: Potential Suspicious Windows Feature Enabled
// ID: 55c925c1-7195-426b-a136-a9396800e29b
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-09-10
// Tags: attack.stealth
// Description: Detects usage of the built-in PowerShell cmdlet "Enable-WindowsOptionalFeature" used as a Deployment Image Servicing and Management tool.
// Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
// Converted by: Sigma Universal SIEM/EDR CLI

(((ScriptBlockText contains "Enable-WindowsOptionalFeature" AND ScriptBlockText contains "-Online" AND ScriptBlockText contains "-FeatureName")) AND ((ScriptBlockText contains "TelnetServer" OR ScriptBlockText contains "Internet-Explorer-Optional-amd64" OR ScriptBlockText contains "TFTP" OR ScriptBlockText contains "SMB1Protocol" OR ScriptBlockText contains "Client-ProjFS" OR ScriptBlockText contains "Microsoft-Windows-Subsystem-Linux")))
