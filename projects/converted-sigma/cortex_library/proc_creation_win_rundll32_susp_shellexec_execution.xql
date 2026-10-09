// Title: Suspicious Usage Of ShellExec_RunDLL
// ID: d87bd452-6da1-456e-8155-7dc988157b7d
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-01
// Tags: attack.stealth
// Description: Detects suspicious usage of the ShellExec_RunDLL function to launch other commands as seen in the the raspberry-robin attack
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "ShellExec_RunDLL") and ((action_process_image_command_line contains "\\Desktop\\" or action_process_image_command_line contains "\\Temp\\" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "comspec" or action_process_image_command_line contains "iex" or action_process_image_command_line contains "Invoke-" or action_process_image_command_line contains "msiexec" or action_process_image_command_line contains "odbcconf" or action_process_image_command_line contains "regsvr32")))
