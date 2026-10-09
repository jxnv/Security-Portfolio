// Title: Renamed VsCode Code Tunnel Execution - File Indicator
// ID: d102b8f5-61dc-4e68-bd83-9a3187c67377
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-10-25
// Tags: attack.command-and-control
// Description: Detects the creation of a file with the name "code_tunnel.json" which indicate execution and usage of VsCode tunneling utility by an "Image" or "Process" other than VsCode.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith "\\code_tunnel.json") and not (((action_process_image_path endswith "\\code-tunnel.exe" or action_process_image_path endswith "\\code.exe"))))
