// Title: Suspicious Service Path Modification
// ID: 138d3531-8793-4f50-a2cd-f291b2863d78
// Status: test
// Level: high
// Author: Victor Sergeev, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2019-10-21
// Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
// Description: Detects service path modification via the "sc" binary to a suspicious command or path
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\sc.exe" and (action_process_image_command_line contains "config" and action_process_image_command_line contains "binPath") and (action_process_image_command_line contains "powershell" or action_process_image_command_line contains "cmd " or action_process_image_command_line contains "mshta" or action_process_image_command_line contains "wscript" or action_process_image_command_line contains "cscript" or action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "svchost" or action_process_image_command_line contains "dllhost" or action_process_image_command_line contains "cmd.exe /c" or action_process_image_command_line contains "cmd.exe /k" or action_process_image_command_line contains "cmd.exe /r" or action_process_image_command_line contains "cmd /c" or action_process_image_command_line contains "cmd /k" or action_process_image_command_line contains "cmd /r" or action_process_image_command_line contains "C:\\Users\\Public" or action_process_image_command_line contains "\\Downloads\\" or action_process_image_command_line contains "\\Desktop\\" or action_process_image_command_line contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" or action_process_image_command_line contains "C:\\Windows\\TEMP\\" or action_process_image_command_line contains "\\AppData\\Local\\Temp"))
