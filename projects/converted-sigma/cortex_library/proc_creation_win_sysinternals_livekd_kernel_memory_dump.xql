// Title: Kernel Memory Dump Via LiveKD
// ID: c7746f1c-47d3-43d6-8c45-cd1e54b6b0a2
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-16
// Tags: attack.stealth
// Description: Detects execution of LiveKD with the "-m" flag to potentially dump the kernel memory
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -m") and (((action_process_image_path endswith "\\livekd.exe" or action_process_image_path endswith "\\livekd64.exe")) or (action_process_image_name = "livekd.exe")))
