// Title: Remote Access Tool - ScreenConnect Remote Command Execution
// ID: b1f73849-6329-4069-bc8f-78a604bb8b23
// Status: test
// Level: low
// Author: Ali Alwashali
// Date: 2023-10-10
// Tags: attack.execution, attack.t1059.003
// Description: Detects the execution of a system command via the ScreenConnect RMM service.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "\\TEMP\\ScreenConnect\\") and ((action_process_image_path endswith "\\cmd.exe") or (action_process_image_name = "Cmd.Exe")) and (actor_process_image_path endswith "\\ScreenConnect.ClientService.exe"))
