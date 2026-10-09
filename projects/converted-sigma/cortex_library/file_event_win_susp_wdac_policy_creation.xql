// Title: Potentially Suspicious WDAC Policy File Creation
// ID: 1d2de8a6-4803-4fde-b85b-f58f3aa7a705
// Status: experimental
// Level: medium
// Author: X__Junior
// Date: 2025-02-07
// Tags: attack.defense-impairment
// Description: Detects suspicious Windows Defender Application Control (WDAC) policy file creation from abnormal processes that could be abused by attacker to block EDR/AV components while allowing their own malicious code to run on the system.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "\\Windows\\System32\\CodeIntegrity\\") and not (((((action_process_image_command_line contains "ConvertFrom-CIPolicy -XmlFilePath" and action_process_image_command_line contains "-BinaryFilePath ")) or (action_process_image_command_line contains "CiTool --update-policy") or ((action_process_image_command_line contains "Copy-Item -Path" and action_process_image_command_line contains "-Destination"))) or ((action_process_image_path endswith "\\Microsoft.ConfigurationManagement.exe" or action_process_image_path endswith "\\WDAC Wizard.exe" or action_process_image_path endswith "C:\\Program Files\\PowerShell\\7-preview\\pwsh.exe" or action_process_image_path endswith "C:\\Program Files\\PowerShell\\7\\pwsh.exe" or action_process_image_path endswith "C:\\Windows\\System32\\dllhost.exe" or action_process_image_path endswith "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe" or action_process_image_path endswith "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" or action_process_image_path endswith "C:\\Windows\\SysWOW64\\dllhost.exe" or action_process_image_path endswith "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell_ise.exe" or action_process_image_path endswith "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe")) or (action_process_image_path = "System") or (action_process_image_path = "C:\\Windows\\System32\\wuauclt.exe") or ((action_process_image_path = "C:\\Windows\\UUS\\arm64\\wuaucltcore.exe" or action_process_image_path = "C:\\Windows\\UUS\\Packages\\Preview\\arm64\\wuaucltcore.exe")))))
