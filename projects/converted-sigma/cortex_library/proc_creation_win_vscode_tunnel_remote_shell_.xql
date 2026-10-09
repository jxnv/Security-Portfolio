// Title: Visual Studio Code Tunnel Shell Execution
// ID: f4a623c2-4ef5-4c33-b811-0642f702c9f1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-10-25
// Tags: attack.command-and-control, attack.t1071.001
// Description: Detects the execution of a shell (powershell, bash, wsl...) via Visual Studio Code tunnel. Attackers can abuse this functionality to establish a C2 channel and execute arbitrary commands on the system.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path contains "\\servers\\Stable-" and actor_process_image_path endswith "\\server\\node.exe" and actor_process_command_line contains ".vscode-server") and (((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and action_process_image_command_line contains "\\terminal\\browser\\media\\shellIntegration.ps1") or ((action_process_image_path endswith "\\wsl.exe" or action_process_image_path endswith "\\bash.exe"))))
