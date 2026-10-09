// Title: Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Location
// ID: cc368ed0-2411-45dc-a222-510ace303cb2
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-25
// Tags: attack.stealth, attack.t1218.009
// Description: Detects potentially suspicious execution of the Regasm/Regsvcs utilities from a potentially suspicious location
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" or action_process_image_command_line contains "\\PerfLogs\\" or action_process_image_command_line contains "\\Users\\Public\\" or action_process_image_command_line contains "\\Windows\\Temp\\")) and (((action_process_image_path endswith "\\Regsvcs.exe" or action_process_image_path endswith "\\Regasm.exe")) or ((action_process_image_name = "RegSvcs.exe" or action_process_image_name = "RegAsm.exe"))))
