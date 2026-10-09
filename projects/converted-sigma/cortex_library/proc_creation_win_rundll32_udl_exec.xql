// Title: Potentially Suspicious Rundll32.EXE Execution of UDL File
// ID: 0ea52357-cd59-4340-9981-c46c7e900428
// Status: test
// Level: medium
// Author: @kostastsale
// Date: 2024-08-16
// Tags: attack.execution, attack.command-and-control, attack.stealth, attack.t1218.011, attack.t1071
// Description: Detects the execution of rundll32.exe with the oledb32.dll library to open a UDL file.
// Threat actors can abuse this technique as a phishing vector to capture authentication credentials or other sensitive data.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "oledb32.dll" and action_process_image_command_line contains ",OpenDSLFile " and action_process_image_command_line contains "\\\\Users\\\\*\\\\Downloads\\\\") and action_process_image_command_line endswith ".udl") and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")) and (actor_process_image_path endswith "\\explorer.exe"))
