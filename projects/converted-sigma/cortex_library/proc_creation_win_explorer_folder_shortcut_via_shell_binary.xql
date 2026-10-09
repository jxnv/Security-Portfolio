// Title: File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell
// ID: c3d76afc-93df-461e-8e67-9b2bad3f2ac4
// Status: test
// Level: high
// Author: @Kostastsale
// Date: 2022-12-22
// Tags: attack.discovery, attack.t1135
// Description: Detects the initial execution of "cmd.exe" which spawns "explorer.exe" with the appropriate command line arguments for opening the "My Computer" folder.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\cmd.exe" or actor_process_image_path endswith "\\powershell.exe" or actor_process_image_path endswith "\\pwsh.exe") and action_process_image_path endswith "\\explorer.exe" and action_process_image_command_line contains "shell:mycomputerfolder")
