// Title: Use of W32tm as Timer
// ID: 6da2c9f5-7c53-401b-aacb-92c040ce1215
// Status: test
// Level: high
// Author: frack113
// Date: 2022-09-25
// Tags: attack.discovery, attack.t1124
// Description: When configured with suitable command line arguments, w32tm can act as a delay mechanism
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/stripchart" and action_process_image_command_line contains "/computer:" and action_process_image_command_line contains "/period:" and action_process_image_command_line contains "/dataonly" and action_process_image_command_line contains "/samples:")) and ((action_process_image_path endswith "\\w32tm.exe") or (action_process_image_name = "w32time.dll")))
