// Title: Suspicious Uninstall of Windows Defender Feature via PowerShell
// ID: c443012c-7928-43bf-ac20-7eda5efe61ad
// Status: experimental
// Level: high
// Author: yxinmiracle
// Date: 2025-08-22
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the use of PowerShell with Uninstall-WindowsFeature or Remove-WindowsFeature cmdlets to disable or remove the Windows Defender GUI feature, a common technique used by adversaries to evade defenses.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "Windows-Defender") and ((action_process_image_command_line contains "Uninstall-WindowsFeature" or action_process_image_command_line contains "Remove-WindowsFeature")) and (((action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "PowerShell_ISE.EXE" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll"))))
