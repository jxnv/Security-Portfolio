// Title: Office Macro File Creation From Suspicious Process
// ID: b1c50487-1967-4315-a026-6491686d860e
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-01-23
// Tags: attack.initial-access, attack.t1566.001
// Description: Detects the creation of a office macro file from a a suspicious process
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\cscript.exe" or action_process_image_path endswith "\\mshta.exe" or action_process_image_path endswith "\\regsvr32.exe" or action_process_image_path endswith "\\rundll32.exe" or action_process_image_path endswith "\\wscript.exe")) or ((actor_process_image_path endswith "\\cscript.exe" or actor_process_image_path endswith "\\mshta.exe" or actor_process_image_path endswith "\\regsvr32.exe" or actor_process_image_path endswith "\\rundll32.exe" or actor_process_image_path endswith "\\wscript.exe"))) and ((action_file_path endswith ".docm" or action_file_path endswith ".dotm" or action_file_path endswith ".xlsm" or action_file_path endswith ".xltm" or action_file_path endswith ".potm" or action_file_path endswith ".pptm")))
