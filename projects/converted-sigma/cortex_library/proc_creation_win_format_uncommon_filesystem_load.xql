// Title: Uncommon FileSystem Load Attempt By Format.com
// ID: 9fb6b26e-7f9e-4517-a48b-8cac4a1b6c60
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-04
// Tags: attack.stealth
// Description: Detects the execution of format.com with an uncommon filesystem selection that could indicate a defense evasion activity in which "format.com" is used to load malicious DLL files or other programs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\format.com" and action_process_image_command_line contains "/fs:") and not (((action_process_image_command_line contains "/fs:exFAT" or action_process_image_command_line contains "/fs:FAT" or action_process_image_command_line contains "/fs:NTFS" or action_process_image_command_line contains "/fs:ReFS" or action_process_image_command_line contains "/fs:UDF"))))
