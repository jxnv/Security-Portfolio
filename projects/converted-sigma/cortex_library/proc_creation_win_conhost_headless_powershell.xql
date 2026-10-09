// Title: Powershell Executed From Headless ConHost Process
// ID: 056c7317-9a09-4bd4-9067-d051312752ea
// Status: test
// Level: medium
// Author: Matt Anderson (Huntress)
// Date: 2024-07-23
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1059.003, attack.t1564.003
// Description: Detects the use of powershell commands from headless ConHost window.
// The "--headless" flag hides the windows from the user upon execution.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "--headless" and action_process_image_command_line contains "powershell")) and ((action_process_image_path endswith "\\conhost.exe") or (action_process_image_name = "CONHOST.EXE")))
