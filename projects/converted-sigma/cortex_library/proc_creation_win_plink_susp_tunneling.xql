// Title: Potential RDP Tunneling Via Plink
// ID: f38ce0b9-5e97-4b47-a211-7dc8d8b871da
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-08-04
// Tags: attack.command-and-control, attack.t1572
// Description: Execution of plink to perform data exfiltration and tunneling
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\plink.exe" and action_process_image_command_line contains ":127.0.0.1:3389") or ((action_process_image_path endswith "\\plink.exe" and action_process_image_command_line contains ":3389") and ((action_process_image_command_line contains " -P 443" or action_process_image_command_line contains " -P 22"))))
