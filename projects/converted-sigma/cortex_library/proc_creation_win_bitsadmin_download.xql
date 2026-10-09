// Title: File Download Via Bitsadmin
// ID: d059842b-6b9d-4ed1-b5c3-5b89143c6ede
// Status: test
// Level: medium
// Author: Michael Haag, FPT.EagleEye
// Date: 2017-03-09
// Tags: attack.persistence, attack.execution, attack.stealth, attack.t1197, attack.s0190, attack.t1036.003, attack.command-and-control, attack.t1105
// Description: Detects usage of bitsadmin downloading a file
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\bitsadmin.exe") or (action_process_image_name = "bitsadmin.exe")) and ((action_process_image_command_line contains " /transfer ") or (((action_process_image_command_line contains " /create " or action_process_image_command_line contains " /addfile ")) and (action_process_image_command_line contains "http"))))
