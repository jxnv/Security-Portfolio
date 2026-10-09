// Title: Insecure Transfer Via Curl.EXE
// ID: cb9cc1d1-e84e-4bdc-b7ad-c31b1b7908ec
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems)
// Date: 2023-06-30
// Tags: attack.execution
// Description: Detects execution of "curl.exe" with the "--insecure" flag.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line ~= "\\s-k\\s") or (action_process_image_command_line contains "--insecure")) and ((action_process_image_path endswith "\\curl.exe") or (action_process_image_name = "curl.exe")))
