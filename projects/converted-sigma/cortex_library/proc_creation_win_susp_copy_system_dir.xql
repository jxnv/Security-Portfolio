// Title: Suspicious Copy From or To System Directory
// ID: fff9d2b7-e11c-4a69-93d3-40ef66189767
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Markus Neis, Tim Shelton (HAWK.IO), Nasreddine Bencherchali (Nextron Systems)
// Date: 2020-07-03
// Tags: attack.stealth, attack.t1036.003
// Description: Detects a suspicious copy operation that tries to copy a program from system (System32, SysWOW64, WinSxS) directories to another on disk.
// Often used to move LOLBINs such as 'certutil' or 'desktopimgdownldr' to a different location with a different name in order to bypass detections based on locations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\cmd.exe" and action_process_image_command_line contains "copy ") or (((action_process_image_path endswith "\\robocopy.exe" or action_process_image_path endswith "\\xcopy.exe")) or ((action_process_image_name = "robocopy.exe" or action_process_image_name = "XCOPY.EXE"))) or ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains "copy-item" or action_process_image_command_line contains " copy " or action_process_image_command_line contains "cpi " or action_process_image_command_line contains " cp "))) and (action_process_image_command_line ~= "\\s['\"]?C:\\\\Windows\\\\(?:System32|SysWOW64|WinSxS)") and not ((action_process_image_path endswith "\\cmd.exe" and (action_process_image_command_line contains "/c copy" and action_process_image_command_line contains "\\Temp\\" and action_process_image_command_line contains "\\avira_system_speedup.exe") and (action_process_image_command_line contains "C:\\Program Files\\Avira\\" or action_process_image_command_line contains "C:\\Program Files (x86)\\Avira\\"))))
