// Title: Suspicious Powercfg Execution To Change Lock Screen Timeout
// ID: f8d6a15e-4bc8-4c27-8e5d-2b10f0b73e5b
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-11-18
// Tags: attack.stealth
// Description: Detects suspicious execution of 'Powercfg.exe' to change lock screen timeout
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\powercfg.exe") or (action_process_image_name = "PowerCfg.exe")) and (((action_process_image_command_line contains "/setacvalueindex " and action_process_image_command_line contains "SCHEME_CURRENT" and action_process_image_command_line contains "SUB_VIDEO" and action_process_image_command_line contains "VIDEOCONLOCK")) or ((action_process_image_command_line contains "-change " and action_process_image_command_line contains "-standby-timeout-"))))
