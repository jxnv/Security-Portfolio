// Title: LOL-Binary Copied From System Directory
// ID: f5d19838-41b5-476c-98d8-ba8af4929ee2
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-29
// Tags: attack.stealth, attack.t1036.003
// Description: Detects a suspicious copy operation that tries to copy a known LOLBIN from system (System32, SysWOW64, WinSxS) directories to another on disk in order to bypass detections based on locations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\cmd.exe" and action_process_image_command_line contains "copy ") or (((action_process_image_path endswith "\\robocopy.exe" or action_process_image_path endswith "\\xcopy.exe")) or ((action_process_image_name = "robocopy.exe" or action_process_image_name = "XCOPY.EXE"))) or ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains "copy-item" or action_process_image_command_line contains " copy " or action_process_image_command_line contains "cpi " or action_process_image_command_line contains " cp "))) and (((action_process_image_command_line contains "\\bitsadmin.exe" or action_process_image_command_line contains "\\calc.exe" or action_process_image_command_line contains "\\certutil.exe" or action_process_image_command_line contains "\\cmdl32.exe" or action_process_image_command_line contains "\\cscript.exe" or action_process_image_command_line contains "\\mshta.exe" or action_process_image_command_line contains "\\rundll32.exe" or action_process_image_command_line contains "\\wscript.exe" or action_process_image_command_line contains "\\ie4uinit.exe")) and ((action_process_image_command_line contains "\\System32" or action_process_image_command_line contains "\\SysWOW64" or action_process_image_command_line contains "\\WinSxS"))))
