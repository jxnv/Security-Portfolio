// Title: Binary Proxy Execution Via Dotnet-Trace.EXE
// ID: 9257c05b-4a4a-48e5-a670-b7b073cf401b
// Status: test
// Level: medium
// Author: Jimmy Bayne (@bohops)
// Date: 2024-01-02
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: Detects commandline arguments for executing a child process via dotnet-trace.exe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-- " and action_process_image_command_line contains "collect")) and ((action_process_image_path endswith "\\dotnet-trace.exe") or (action_process_image_name = "dotnet-trace.dll")))
