// Title: Invoke-Obfuscation Via Use MSHTA
// ID: ac20ae82-8758-4f38-958e-b44a3140ca88
// Status: test
// Level: high
// Author: Nikita Nazarov, oscd.community
// Date: 2020-10-08
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via use MSHTA in Scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "set" and action_process_image_command_line contains "&&" and action_process_image_command_line contains "mshta" and action_process_image_command_line contains "vbscript:createobject" and action_process_image_command_line contains ".run" and action_process_image_command_line contains "(window.close)"))
