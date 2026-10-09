// Title: Replace.exe Usage
// ID: 9292293b-8496-4715-9db6-37028dcda4b3
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-03-06
// Tags: attack.command-and-control, attack.t1105
// Description: Detects the use of Replace.exe which can be used to replace file with another file
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\replace.exe") and ((action_process_image_command_line contains "-a" or action_process_image_command_line contains "/a")))
