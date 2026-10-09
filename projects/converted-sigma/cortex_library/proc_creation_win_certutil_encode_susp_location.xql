// Title: File In Suspicious Location Encoded To Base64 Via Certutil.EXE
// ID: 82a6714f-4899-4f16-9c1e-9a333544d4c3
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-15
// Tags: attack.stealth, attack.t1027
// Description: Detects the execution of certutil with the "encode" flag to encode a file to base64 where the files are located in potentially suspicious locations
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-encode" or action_process_image_command_line contains "/encode")) and ((action_process_image_command_line contains "\\AppData\\Roaming\\" or action_process_image_command_line contains "\\Desktop\\" or action_process_image_command_line contains "\\Local\\Temp\\" or action_process_image_command_line contains "\\PerfLogs\\" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "\\Windows\\Temp\\" or action_process_image_command_line contains "$Recycle.Bin")) and ((action_process_image_path endswith "\\certutil.exe") or (action_process_image_name = "CertUtil.exe")))
