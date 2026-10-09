// Title: Application Removed Via Wmic.EXE
// ID: b53317a0-8acf-4fd1-8de8-a5401e776b96
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-28
// Tags: attack.execution, attack.t1047
// Description: Detects the removal or uninstallation of an application via "Wmic.EXE".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "call" and action_process_image_command_line contains "uninstall")) and ((action_process_image_path endswith "\\WMIC.exe") or (action_process_image_name = "wmic.exe")))
