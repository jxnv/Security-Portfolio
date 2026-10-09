// Title: Process Memory Dump Via Dotnet-Dump
// ID: 53d8d3e1-ca33-4012-adf3-e05a4d652e34
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-14
// Tags: attack.stealth, attack.t1218
// Description: Detects the execution of "dotnet-dump" with the "collect" flag. The execution could indicate potential process dumping of critical processes such as LSASS.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "collect") and ((action_process_image_path endswith "\\dotnet-dump.exe") or (action_process_image_name = "dotnet-dump.dll")))
