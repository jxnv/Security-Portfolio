// Title: Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Extension
// ID: e9f8f8cc-07cc-4e81-b724-f387db9175e4
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-13
// Tags: attack.stealth, attack.t1218.009
// Description: Detects potentially suspicious execution of the Regasm/Regsvcs utilities with an uncommon extension.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".dat" or action_process_image_command_line contains ".gif" or action_process_image_command_line contains ".jpeg" or action_process_image_command_line contains ".jpg" or action_process_image_command_line contains ".png" or action_process_image_command_line contains ".txt")) and (((action_process_image_path endswith "\\Regsvcs.exe" or action_process_image_path endswith "\\Regasm.exe")) or ((action_process_image_name = "RegSvcs.exe" or action_process_image_name = "RegAsm.exe"))))
