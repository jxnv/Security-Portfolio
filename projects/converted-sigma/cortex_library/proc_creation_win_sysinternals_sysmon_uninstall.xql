// Title: Uninstall Sysinternals Sysmon
// ID: 6a5f68d1-c4b5-46b9-94ee-5324892ea939
// Status: test
// Level: high
// Author: frack113
// Date: 2022-01-12
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects the removal of Sysmon, which could be a potential attempt at defense evasion
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-u" or action_process_image_command_line contains "/u")) and (((action_process_image_path endswith "\\Sysmon64.exe" or action_process_image_path endswith "\\Sysmon64a.exe" or action_process_image_path endswith "\\Sysmon.exe")) or (Description = "System activity monitor")))
