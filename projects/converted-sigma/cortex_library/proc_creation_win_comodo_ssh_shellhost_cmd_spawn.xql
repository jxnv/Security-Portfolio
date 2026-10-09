// Title: OpenEDR Spawning Command Shell
// ID: 7f3a9c2d-4e8b-4a7f-9d3e-5c6f8a9b2e1d
// Status: experimental
// Level: medium
// Author: @kostastsale
// Date: 2026-02-19
// Tags: attack.execution, attack.t1059.003, attack.lateral-movement, attack.t1021.004, attack.command-and-control, attack.t1219
// Description: Detects the OpenEDR ssh-shellhost.exe spawning a command shell (cmd.exe) or PowerShell with PTY (pseudo-terminal) capabilities.
// This may indicate remote command execution through OpenEDR's remote management features, which could be legitimate administrative activity or potential abuse of the remote access tool.
// Threat actors may leverage OpenEDR's remote shell capabilities to execute commands on compromised systems, facilitating lateral movement or other command-and-control operations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "bash" or action_process_image_command_line contains "cmd" or action_process_image_command_line contains "powershell" or action_process_image_command_line contains "pwsh")) and (actor_process_image_path endswith "\\ITSMService.exe" and action_process_image_path endswith "\\ssh-shellhost.exe" and action_process_image_command_line contains "--pty"))
