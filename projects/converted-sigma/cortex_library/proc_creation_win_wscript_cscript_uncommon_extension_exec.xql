// Title: Cscript/Wscript Uncommon Script Extension Execution
// ID: 99b7460d-c9f1-40d7-a316-1f36f61d52ee
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-15
// Tags: attack.execution, attack.t1059.005, attack.t1059.007
// Description: Detects Wscript/Cscript executing a file with an uncommon (i.e. non-script) extension
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".csv" or action_process_image_command_line contains ".dat" or action_process_image_command_line contains ".doc" or action_process_image_command_line contains ".gif" or action_process_image_command_line contains ".jpeg" or action_process_image_command_line contains ".jpg" or action_process_image_command_line contains ".png" or action_process_image_command_line contains ".ppt" or action_process_image_command_line contains ".txt" or action_process_image_command_line contains ".xls" or action_process_image_command_line contains ".xml")) and (((action_process_image_name = "wscript.exe" or action_process_image_name = "cscript.exe")) or ((action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe"))))
