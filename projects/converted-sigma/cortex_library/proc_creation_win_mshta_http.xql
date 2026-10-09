// Title: Remotely Hosted HTA File Executed Via Mshta.EXE
// ID: b98d0db6-511d-45de-ad02-e82a98729620
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-08
// Tags: attack.execution, attack.stealth, attack.t1218.005
// Description: Detects execution of the "mshta" utility with an argument containing the "http" keyword, which could indicate that an attacker is executing a remotely hosted malicious hta file
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "http://" or action_process_image_command_line contains "https://" or action_process_image_command_line contains "ftp://")) and ((action_process_image_path endswith "\\mshta.exe") or (action_process_image_name = "MSHTA.EXE")))
