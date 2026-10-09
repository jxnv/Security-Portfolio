// Title: Windows Defender Context Menu Removed
// ID: b9e8c7d6-a5f4-4e3d-8b1a-9f0c8d7e6a5b
// Status: experimental
// Level: high
// Author: Matt Anderson (Huntress)
// Date: 2025-07-09
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the use of reg.exe or PowerShell to delete the Windows Defender context menu handler registry keys.
// This action removes the "Scan with Microsoft Defender" option from the right-click menu for files, directories, and drives.
// Attackers may use this technique to hinder manual, on-demand scans and reduce the visibility of the security product.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "del" or action_process_image_command_line contains "Remove-Item" or action_process_image_command_line contains "ri ")) and (((action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\reg.exe")) or ((action_process_image_name = "powershell_ise.EXE" or action_process_image_name = "PowerShell.EXE" or action_process_image_name = "pwsh.dll" or action_process_image_name = "reg.exe"))) and (action_process_image_command_line contains "\\shellex\\ContextMenuHandlers\\EPP"))
