// Title: Use Of The SFTP.EXE Binary As A LOLBIN
// ID: a85ffc3a-e8fd-4040-93bf-78aff284d801
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-11-10
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: Detects the usage of the "sftp.exe" binary as a LOLBIN by abusing the "-D" flag
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\sftp.exe" and (action_process_image_command_line contains " -D .." or action_process_image_command_line contains " -D C:\\"))
