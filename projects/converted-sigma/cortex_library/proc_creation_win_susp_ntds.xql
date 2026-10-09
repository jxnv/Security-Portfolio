// Title: Suspicious Process Patterns NTDS.DIT Exfil
// ID: 8bc64091-6875-4881-aaf9-7bd25b5dda08
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-11
// Tags: attack.credential-access, attack.t1003.003
// Description: Detects suspicious process patterns used in NTDS.DIT exfiltration
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "ac i ntds" and action_process_image_command_line contains "create full")) or ((action_process_image_command_line contains "/c copy " and action_process_image_command_line contains "\\windows\\ntds\\ntds.dit")) or ((action_process_image_command_line contains "activate instance ntds" and action_process_image_command_line contains "create full")) or ((action_process_image_command_line contains "powershell" and action_process_image_command_line contains "ntds.dit")) or (((action_process_image_path endswith "\\NTDSDump.exe" or action_process_image_path endswith "\\NTDSDumpEx.exe")) or ((action_process_image_command_line contains "ntds.dit" and action_process_image_command_line contains "system.hiv")) or (action_process_image_command_line contains "NTDSgrab.ps1"))) or ((((actor_process_image_path contains "\\apache" or actor_process_image_path contains "\\tomcat" or actor_process_image_path contains "\\AppData\\" or actor_process_image_path contains "\\Temp\\" or actor_process_image_path contains "\\Public\\" or actor_process_image_path contains "\\PerfLogs\\")) or ((action_process_image_path contains "\\apache" or action_process_image_path contains "\\tomcat" or action_process_image_path contains "\\AppData\\" or action_process_image_path contains "\\Temp\\" or action_process_image_path contains "\\Public\\" or action_process_image_path contains "\\PerfLogs\\"))) and (action_process_image_command_line contains "ntds.dit")))
