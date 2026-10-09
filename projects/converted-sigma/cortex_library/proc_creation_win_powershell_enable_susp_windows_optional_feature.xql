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

dataset = xdr_data | filter (((action_process_image_command_line contains "Enable-WindowsOptionalFeature" and action_process_image_command_line contains "-Online" and action_process_image_command_line contains "-FeatureName")) and ((action_process_image_command_line contains "TelnetServer" or action_process_image_command_line contains "Internet-Explorer-Optional-amd64" or action_process_image_command_line contains "TFTP" or action_process_image_command_line contains "SMB1Protocol" or action_process_image_command_line contains "Client-ProjFS" or action_process_image_command_line contains "Microsoft-Windows-Subsystem-Linux")))
