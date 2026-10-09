// Title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION
// ID: e9f55347-2928-4c06-88e5-1a7f8169942e
// Status: test
// Level: high
// Author: Timur Zinniatullin, oscd.community
// Date: 2020-10-13
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via VAR++ LAUNCHER
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "&&set" and action_process_image_command_line contains "cmd" and action_process_image_command_line contains "/c" and action_process_image_command_line contains "-f") and (action_process_image_command_line contains "{0}" or action_process_image_command_line contains "{1}" or action_process_image_command_line contains "{2}" or action_process_image_command_line contains "{3}" or action_process_image_command_line contains "{4}" or action_process_image_command_line contains "{5}"))
