// Title: Harvesting Of Wifi Credentials Via Netsh.EXE
// ID: 42b1a5b8-353f-4f10-b256-39de4467faff
// Status: test
// Level: medium
// Author: Andreas Hunkeler (@Karneades), oscd.community
// Date: 2020-04-20
// Tags: attack.discovery, attack.credential-access, attack.t1040
// Description: Detect the harvesting of wifi credentials using netsh.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "wlan" and action_process_image_command_line contains " s" and action_process_image_command_line contains " p" and action_process_image_command_line contains " k" and action_process_image_command_line contains "=clear")) and ((action_process_image_path endswith "\\netsh.exe") or (action_process_image_name = "netsh.exe")))
