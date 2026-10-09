// Title: Suspicious Velociraptor Child Process
// ID: 4bc90587-e6ca-4b41-be0b-ed4d04e4ed0c
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-08-29
// Tags: attack.command-and-control, attack.persistence, attack.t1219
// Description: Detects the suspicious use of the Velociraptor DFIR tool to execute other tools or download additional payloads, as seen in a campaign where it was abused for remote access and to stage further attacks.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\Velociraptor.exe") and (((action_process_image_command_line contains "msiexec" and action_process_image_command_line contains "/i" and action_process_image_command_line contains "http")) or ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\powershell_ise.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains "Invoke-WebRequest " or action_process_image_command_line contains "IWR " or action_process_image_command_line contains ".DownloadFile" or action_process_image_command_line contains ".DownloadString")) or ((action_process_image_command_line contains "code.exe" and action_process_image_command_line contains "tunnel" and action_process_image_command_line contains "--accept-server-license-terms"))))
