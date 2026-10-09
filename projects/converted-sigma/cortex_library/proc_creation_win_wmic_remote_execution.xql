// Title: WMIC Remote Command Execution
// ID: 7773b877-5abb-4a3e-b9c9-fd0369b59b00
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-14
// Tags: attack.execution, attack.t1047
// Description: Detects the execution of WMIC to query information on a remote system
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "/node:" or action_process_image_command_line contains "-node:")) and ((action_process_image_path endswith "\\WMIC.exe") or (action_process_image_name = "wmic.exe"))) and not (((action_process_image_command_line contains "localhost" or action_process_image_command_line contains "127.0.0.1"))))
