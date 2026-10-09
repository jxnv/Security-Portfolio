// Title: New DLL Registered Via Odbcconf.EXE
// ID: 9f0a8bf3-a65b-440a-8c1e-5cb1547c8e70
// Status: test
// Level: medium
// Author: Kirill Kiryanov, Beyu Denis, Daniil Yugoslavskiy, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-22
// Tags: attack.stealth, attack.t1218.008
// Description: Detects execution of "odbcconf" with "REGSVR" in order to register a new DLL (equivalent to running regsvr32). Attackers abuse this to install and run malicious DLLs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "REGSVR " and action_process_image_command_line contains ".dll")) and ((action_process_image_path endswith "\\odbcconf.exe") or (action_process_image_name = "odbcconf.exe")))
