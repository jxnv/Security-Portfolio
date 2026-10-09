// Title: Suspicious File Downloaded From Direct IP Via Certutil.EXE
// ID: 13e6fe51-d478-4c7e-b0f2-6da9b400a829
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-15
// Tags: attack.stealth, attack.t1027, attack.command-and-control, attack.t1105
// Description: Detects the execution of certutil with certain flags that allow the utility to download files from direct IPs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "urlcache " or action_process_image_command_line contains "verifyctl " or action_process_image_command_line contains "URL ")) and ((action_process_image_command_line contains "://1" or action_process_image_command_line contains "://2" or action_process_image_command_line contains "://3" or action_process_image_command_line contains "://4" or action_process_image_command_line contains "://5" or action_process_image_command_line contains "://6" or action_process_image_command_line contains "://7" or action_process_image_command_line contains "://8" or action_process_image_command_line contains "://9")) and ((action_process_image_path endswith "\\certutil.exe") or (action_process_image_name = "CertUtil.exe"))) and not ((action_process_image_command_line contains "://7-")))
