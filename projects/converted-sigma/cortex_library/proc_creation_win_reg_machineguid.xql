// Title: Suspicious Query of MachineGUID
// ID: f5240972-3938-4e56-8e4b-e33893176c1f
// Status: test
// Level: low
// Author: frack113
// Date: 2022-01-01
// Tags: attack.discovery, attack.t1082
// Description: Use of reg to get MachineGuid information
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\reg.exe" and (action_process_image_command_line contains "SOFTWARE\\Microsoft\\Cryptography" and action_process_image_command_line contains "/v " and action_process_image_command_line contains "MachineGuid"))
