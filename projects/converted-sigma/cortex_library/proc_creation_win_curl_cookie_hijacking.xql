// Title: Potential Cookies Session Hijacking
// ID: 5a6e1e16-07de-48d8-8aae-faa766c05e88
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-07-27
// Tags: attack.execution
// Description: Detects execution of "curl.exe" with the "-c" flag in order to save cookie data.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line ~= "\\s-c\\s") or (action_process_image_command_line contains "--cookie-jar")) and ((action_process_image_path endswith "\\curl.exe") or (action_process_image_name = "curl.exe")))
