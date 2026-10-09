// Title: Suspicious ClickFix/FileFix Execution Pattern
// ID: d487ed4a-fd24-436d-a0b2-f4e95f7b2635
// Status: experimental
// Level: high
// Author: montysecurity, Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-11-19
// Tags: attack.execution, attack.t1204.001, attack.t1204.004
// Description: Detects suspicious execution patterns where users are tricked into running malicious commands via clipboard manipulation, either through the Windows Run dialog (ClickFix) or File Explorer address bar (FileFix).
// Attackers leverage social engineering campaigns—such as fake CAPTCHA challenges or urgent alerts—encouraging victims to paste clipboard contents, often executing mshta.exe, powershell.exe, or similar commands to infect systems.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "account" or action_process_image_command_line contains "anti-bot" or action_process_image_command_line contains "botcheck" or action_process_image_command_line contains "captcha" or action_process_image_command_line contains "challenge" or action_process_image_command_line contains "confirmation" or action_process_image_command_line contains "fraud" or action_process_image_command_line contains "human" or action_process_image_command_line contains "identification" or action_process_image_command_line contains "identificator" or action_process_image_command_line contains "identity" or action_process_image_command_line contains "robot" or action_process_image_command_line contains "validation" or action_process_image_command_line contains "verification" or action_process_image_command_line contains "verify")) and (actor_process_image_path endswith "\\explorer.exe" and action_process_image_command_line contains "#"))
