// Title: Remote Code Execute via Winrm.vbs
// ID: 9df0dd3a-1a5c-47e3-a2bc-30ed177646a0
// Status: test
// Level: medium
// Author: Julia Fomina, oscd.community
// Date: 2020-10-07
// Tags: attack.stealth, attack.t1216
// Description: Detects an attempt to execute code or create service on remote host via winrm.vbs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "winrm" and action_process_image_command_line contains "invoke Create wmicimv2/Win32_" and action_process_image_command_line contains "-r:http")) and ((action_process_image_path endswith "\\cscript.exe") or (action_process_image_name = "cscript.exe")))
