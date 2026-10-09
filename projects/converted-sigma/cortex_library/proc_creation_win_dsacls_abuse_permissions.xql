// Title: Potentially Over Permissive Permissions Granted Using Dsacls.EXE
// ID: 01c42d3c-242d-4655-85b2-34f1739632f7
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.stealth, attack.t1218
// Description: Detects usage of Dsacls to grant over permissive permissions
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " /G ") and ((action_process_image_path endswith "\\dsacls.exe") or (action_process_image_name = "DSACLS.EXE")) and ((action_process_image_command_line contains "GR" or action_process_image_command_line contains "GE" or action_process_image_command_line contains "GW" or action_process_image_command_line contains "GA" or action_process_image_command_line contains "WP" or action_process_image_command_line contains "WD")))
