// Title: User Shell Folders Registry Modification via CommandLine
// ID: 8f3ab69a-aa22-4943-aa58-e0a52fdf6818
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-01-05
// Tags: attack.persistence, attack.privilege-escalation, attack.defense-impairment, attack.t1547.001, attack.t1112
// Description: Detects modifications to User Shell Folders registry values via reg.exe or PowerShell, which could indicate persistence attempts.
// Attackers may modify User Shell Folders registry values to point to malicious executables or scripts that will be executed during startup.
// This technique is often used to maintain persistence on a compromised system by ensuring that malicious payloads are executed automatically.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " add " or action_process_image_command_line contains "New-ItemProperty" or action_process_image_command_line contains "Set-ItemProperty" or action_process_image_command_line contains "si ")) and ((action_process_image_command_line contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" or action_process_image_command_line contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders")) and (action_process_image_command_line contains "Startup") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\reg.exe")) or ((action_process_image_name = "powershell.exe" or action_process_image_name = "pwsh.dll" or action_process_image_name = "reg.exe"))))
