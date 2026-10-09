// Title: Suspicious Extrac32 Execution
// ID: aa8e035d-7be4-48d3-a944-102aec04400d
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-11-26
// Tags: attack.command-and-control, attack.t1105
// Description: Download or Copy file with Extrac32
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains ".cab") and ((action_process_image_command_line contains "extrac32.exe") or (action_process_image_path endswith "\\extrac32.exe") or (action_process_image_name = "extrac32.exe")) and ((action_process_image_command_line contains "/C" or action_process_image_command_line contains "/Y" or action_process_image_command_line contains " \\\\\\\\")))
