// Title: Potential PowerShell Downgrade Attack
// ID: b3512211-c67e-4707-bedc-66efc7848863
// Status: test
// Level: medium
// Author: Harish Segar (rule)
// Date: 2020-03-20
// Tags: attack.execution, attack.t1059.001
// Description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\powershell.exe" and (action_process_image_command_line contains " -version 2 " or action_process_image_command_line contains " -versio 2 " or action_process_image_command_line contains " -versi 2 " or action_process_image_command_line contains " -vers 2 " or action_process_image_command_line contains " -ver 2 " or action_process_image_command_line contains " -ve 2 " or action_process_image_command_line contains " -v 2 "))
