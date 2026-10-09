// Title: Suspicious WSL InstallLocation Registry Key Modification Via CommandLine
// ID: f9f62824-de4e-40ca-afe7-8358f76a876d
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-05-05
// Tags: attack.stealth, attack.defense-impairment, attack.persistence, attack.t1112, attack.t1218
// Description: Detects the use of reg.exe or PowerShell to modify the WSL InstallLocation registry key via command-line arguments.
// Legitimate modifications to this key are performed exclusively by the Windows Installer (msiexec.exe) during WSL package installation or update.
// Manual use of reg.exe or PowerShell to set this value strongly indicates an attempt to redirect WSL execution to a malicious binary.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " add " or action_process_image_command_line contains "New-ItemProperty" or action_process_image_command_line contains "Set-ItemProperty" or action_process_image_command_line contains "sp ")) and ((action_process_image_command_line contains "\\Lxss\\MSI" or action_process_image_command_line contains "/Lxss/MSI")) and (action_process_image_command_line contains "InstallLocation") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe" or action_process_image_path endswith "\\reg.exe")) or ((action_process_image_name = "powershell.exe" or action_process_image_name = "pwsh.dll" or action_process_image_name = "reg.exe"))))
