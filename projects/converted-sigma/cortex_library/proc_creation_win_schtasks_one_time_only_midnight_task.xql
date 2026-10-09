// Title: Uncommon One Time Only Scheduled Task At 00:00
// ID: 970823b7-273b-460a-8afc-3a6811998529
// Status: test
// Level: high
// Author: pH-T (Nextron Systems)
// Date: 2022-07-15
// Tags: attack.execution, attack.persistence, attack.privilege-escalation, attack.t1053.005
// Description: Detects scheduled task creation events that include suspicious actions, and is run once at 00:00
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "wscript" or action_process_image_command_line contains "vbscript" or action_process_image_command_line contains "cscript" or action_process_image_command_line contains "wmic " or action_process_image_command_line contains "wmic.exe" or action_process_image_command_line contains "regsvr32.exe" or action_process_image_command_line contains "powershell" or action_process_image_command_line contains "\\AppData\\")) and ((action_process_image_path contains "\\schtasks.exe") or (action_process_image_name = "schtasks.exe")) and ((action_process_image_command_line contains "once" and action_process_image_command_line contains "00:00")))
