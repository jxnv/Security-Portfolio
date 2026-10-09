// Title: Suspicious Curl File Upload - Linux
// ID: 00b90cc1-17ec-402c-96ad-3a8117d7a582
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Cedric MAURUGEON (Update)
// Date: 2022-09-15
// Tags: attack.exfiltration, attack.command-and-control, attack.t1567, attack.t1105
// Description: Detects a suspicious curl process start the adds a file to a web request
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_command_line contains " --form" or action_process_image_command_line contains " --upload-file " or action_process_image_command_line contains " --data " or action_process_image_command_line contains " --data-")) or (action_process_image_command_line ~= "\\s-[FTd]\\s")) and (action_process_image_path endswith "/curl")) and not (((action_process_image_command_line contains "://localhost" or action_process_image_command_line contains "://127.0.0.1"))))
