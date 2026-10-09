// Title: Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths
// ID: c74c0390-3e20-41fd-a69a-128f0275a5ea
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-05
// Tags: attack.execution
// Description: Detects the execution of the "wusa.exe" (Windows Update Standalone Installer) utility to extract ".cab" files using the "/extract" argument from potentially suspicious paths.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ":\\PerfLogs\\" or action_process_image_command_line contains ":\\Users\\Public\\" or action_process_image_command_line contains ":\\Windows\\Temp\\" or action_process_image_command_line contains "\\Appdata\\Local\\Temp\\")) and (action_process_image_path endswith "\\wusa.exe" and action_process_image_command_line contains "/extract:"))
