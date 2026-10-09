// Title: Run PowerShell Script from Redirected Input Stream
// ID: c83bf4b5-cdf0-437c-90fa-43d734f7c476
// Status: test
// Level: high
// Author: Moriarty Meng (idea), Anton Kutepov (rule), oscd.community
// Date: 2020-10-17
// Tags: attack.execution, attack.t1059
// Description: Detects PowerShell script execution via input stream redirect
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and action_process_image_command_line ~= "\\s-\\s*<")
