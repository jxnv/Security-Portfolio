// Title: Windows Defender Definition Files Removed
// ID: 9719a8aa-401c-41af-8108-ced7ec9cd75c
// Status: test
// Level: high
// Author: frack113
// Date: 2021-07-07
// Tags: attack.defense-impairment, attack.t1685
// Description: Adversaries may disable security tools to avoid possible detection of their tools and activities by removing Windows Defender Definition Files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -RemoveDefinitions" and action_process_image_command_line contains " -All")) and ((action_process_image_path endswith "\\MpCmdRun.exe") or (action_process_image_name = "MpCmdRun.exe")))
