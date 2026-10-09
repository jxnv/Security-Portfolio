// Title: Schtasks From Suspicious Folders
// ID: 8a8379b8-780b-4dbf-b1e9-31c8d112fefb
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-04-15
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1053.005
// Description: Detects scheduled task creations that have suspicious action command and folder combinations
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "C:\\ProgramData\\" or action_process_image_command_line contains "%ProgramData%")) and ((action_process_image_command_line contains "powershell" or action_process_image_command_line contains "pwsh" or action_process_image_command_line contains "cmd /c " or action_process_image_command_line contains "cmd /k " or action_process_image_command_line contains "cmd /r " or action_process_image_command_line contains "cmd.exe /c " or action_process_image_command_line contains "cmd.exe /k " or action_process_image_command_line contains "cmd.exe /r ")) and (action_process_image_command_line contains " /create ") and ((action_process_image_path endswith "\\schtasks.exe") or (action_process_image_name = "schtasks.exe")))
