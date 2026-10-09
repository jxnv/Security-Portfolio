// Title: IIS WebServer Log Deletion via CommandLine Utilities
// ID: 0649be4a-aeb0-45b0-b89e-7f1668f6d9c0
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-09-02
// Tags: attack.stealth, attack.t1070
// Description: Detects attempts to delete Internet Information Services (IIS) log files via command line utilities, which is a common defense evasion technique used by attackers to cover their tracks.
// Threat actors often abuse vulnerabilities in web applications hosted on IIS servers to gain initial access and later delete IIS logs to evade detection.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "del " or action_process_image_command_line contains "erase " or action_process_image_command_line contains "rm " or action_process_image_command_line contains "remove-item " or action_process_image_command_line contains "rmdir ")) and (action_process_image_command_line contains "\\inetpub\\logs\\") and (((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe")) or ((action_process_image_name = "cmd.exe" or action_process_image_name = "powershell.exe" or action_process_image_name = "powershell_ise.exe" or action_process_image_name = "pwsh.dll"))))
