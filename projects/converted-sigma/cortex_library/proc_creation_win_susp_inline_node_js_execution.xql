// Title: Potentially Suspicious Inline JavaScript Execution via NodeJS Binary
// ID: 8537c866-072e-460d-bfff-aaf39cbd73d3
// Status: experimental
// Level: medium
// Author: Microsoft (idea), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-04-21
// Tags: attack.execution, attack.t1059.007
// Description: Detects potentially suspicious inline JavaScript execution using Node.js with specific keywords in the command line.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "http" and action_process_image_command_line contains "execSync" and action_process_image_command_line contains "spawn" and action_process_image_command_line contains "fs" and action_process_image_command_line contains "path" and action_process_image_command_line contains "zlib")) and ((action_process_image_path endswith "\\node.exe") or (action_process_image_name = "node.exe") or (Product = "Node.js")))
