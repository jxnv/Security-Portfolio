// Title: Privilege Escalation via Named Pipe Impersonation
// ID: 9bd04a79-dabe-4f1f-a5ff-92430265c96b
// Status: test
// Level: high
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-27
// Tags: attack.lateral-movement, attack.t1021
// Description: Detects a remote file copy attempt to a hidden network share. This may indicate lateral movement or data staging activity.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "echo" and action_process_image_command_line contains ">" and action_process_image_command_line contains "\\\\\\\\.\\\\pipe\\\\")) and (((action_process_image_path endswith "\\cmd.exe" or action_process_image_path endswith "\\powershell.exe")) or ((action_process_image_name = "Cmd.Exe" or action_process_image_name = "PowerShell.EXE"))))
