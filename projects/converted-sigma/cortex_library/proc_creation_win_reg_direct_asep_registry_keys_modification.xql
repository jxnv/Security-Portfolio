// Title: Direct Autorun Keys Modification
// ID: 24357373-078f-44ed-9ac4-6d334a668a11
// Status: test
// Level: medium
// Author: Victor Sergeev, Daniil Yugoslavskiy, oscd.community, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2019-10-25
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "add") and ((action_process_image_command_line contains "\\software\\Microsoft\\Windows\\CurrentVersion\\Run" or action_process_image_command_line contains "\\software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" or action_process_image_command_line contains "\\software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" or action_process_image_command_line contains "\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit" or action_process_image_command_line contains "\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" or action_process_image_command_line contains "\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" or action_process_image_command_line contains "\\system\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell")) and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe")))
