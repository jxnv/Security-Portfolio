// Title: Suspicious File Encoded To Base64 Via Certutil.EXE
// ID: ea0cdc3e-2239-4f26-a947-4e8f8224e464
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-15
// Tags: attack.stealth, attack.t1027
// Description: Detects the execution of certutil with the "encode" flag to encode a file to base64 where the extensions of the file is suspicious
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-encode" or action_process_image_command_line contains "/encode")) and ((action_process_image_command_line contains ".acl" or action_process_image_command_line contains ".bat" or action_process_image_command_line contains ".doc" or action_process_image_command_line contains ".gif" or action_process_image_command_line contains ".jpeg" or action_process_image_command_line contains ".jpg" or action_process_image_command_line contains ".mp3" or action_process_image_command_line contains ".pdf" or action_process_image_command_line contains ".png" or action_process_image_command_line contains ".ppt" or action_process_image_command_line contains ".tmp" or action_process_image_command_line contains ".xls" or action_process_image_command_line contains ".xml")) and ((action_process_image_path endswith "\\certutil.exe") or (action_process_image_name = "CertUtil.exe")))
