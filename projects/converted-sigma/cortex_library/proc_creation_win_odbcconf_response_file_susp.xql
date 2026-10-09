// Title: Suspicious Response File Execution Via Odbcconf.EXE
// ID: 2d32dd6f-3196-4093-b9eb-1ad8ab088ca5
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-22
// Tags: attack.stealth, attack.t1218.008
// Description: Detects execution of "odbcconf" with the "-f" flag in order to load a response file with a non-".rsp" extension.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -f ") and ((action_process_image_path endswith "\\odbcconf.exe") or (action_process_image_name = "odbcconf.exe"))) and not (((action_process_image_command_line contains ".rsp") or (actor_process_image_path = "C:\\Windows\\System32\\runonce.exe" and action_process_image_path = "C:\\Windows\\System32\\odbcconf.exe" and action_process_image_command_line contains ".exe /E /F \"C:\\WINDOWS\\system32\\odbcconf.tmp\""))))
