// Title: Potentially Suspicious DLL Registered Via Odbcconf.EXE
// ID: ba4cfc11-d0fa-4d94-bf20-7c332c412e76
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-22
// Tags: attack.stealth, attack.t1218.008
// Description: Detects execution of "odbcconf" with the "REGSVR" action where the DLL in question doesn't contain a ".dll" extension. Which is often used as a method to evade defenses.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "REGSVR ") and ((action_process_image_path endswith "\\odbcconf.exe") or (action_process_image_name = "odbcconf.exe"))) and not ((action_process_image_command_line contains ".dll")))
