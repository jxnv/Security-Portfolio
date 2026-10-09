// Title: Potentially Suspicious Office Document Executed From Trusted Location
// ID: f99abdf0-6283-4e71-bd2b-b5c048a94743
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-21
// Tags: attack.stealth, attack.t1202
// Description: Detects the execution of an Office application that points to a document that is located in a trusted location. Attackers often used this to avoid macro security and execute their malicious code.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((((action_process_image_path endswith "\\EXCEL.EXE" or action_process_image_path endswith "\\POWERPNT.EXE" or action_process_image_path endswith "\\WINWORD.exe")) or ((action_process_image_name = "Excel.exe" or action_process_image_name = "POWERPNT.EXE" or action_process_image_name = "WinWord.exe"))) and ((actor_process_image_path endswith "\\explorer.exe" or actor_process_image_path endswith "\\dopus.exe")) and ((action_process_image_command_line contains "\\AppData\\Roaming\\Microsoft\\Templates" or action_process_image_command_line contains "\\AppData\\Roaming\\Microsoft\\Word\\Startup\\" or action_process_image_command_line contains "\\Microsoft Office\\root\\Templates\\" or action_process_image_command_line contains "\\Microsoft Office\\Templates\\"))) and not (((action_process_image_command_line endswith ".dotx" or action_process_image_command_line endswith ".xltx" or action_process_image_command_line endswith ".potx"))))
