// Title: Query Usage To Exfil Data
// ID: 53ef0cef-fa24-4f25-a34a-6c72dfa2e6e2
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-01
// Tags: attack.execution
// Description: Detects usage of "query.exe" a system binary to exfil information such as "sessions" and "processes" for later use
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith ":\\Windows\\System32\\query.exe" and (action_process_image_command_line contains "session >" or action_process_image_command_line contains "process >"))
