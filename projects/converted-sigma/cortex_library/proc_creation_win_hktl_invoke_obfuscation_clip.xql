// Title: Invoke-Obfuscation CLIP+ Launcher
// ID: b222df08-0e07-11eb-adc1-0242ac120002
// Status: test
// Level: high
// Author: Jonathan Cheong, oscd.community
// Date: 2020-10-13
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated use of Clip.exe to execute PowerShell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "cmd" and action_process_image_command_line contains "&&" and action_process_image_command_line contains "clipboard]::" and action_process_image_command_line contains "-f") and (action_process_image_command_line contains "/c" or action_process_image_command_line contains "/r"))
