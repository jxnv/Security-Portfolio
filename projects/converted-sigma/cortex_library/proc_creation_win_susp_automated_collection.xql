// Title: Automated Collection Command Prompt
// ID: f576a613-2392-4067-9d1a-9345fb58d8d1
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-07-28
// Tags: attack.collection, attack.t1119, attack.credential-access, attack.t1552.001
// Description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".doc" or action_process_image_command_line contains ".docx" or action_process_image_command_line contains ".xls" or action_process_image_command_line contains ".xlsx" or action_process_image_command_line contains ".ppt" or action_process_image_command_line contains ".pptx" or action_process_image_command_line contains ".rtf" or action_process_image_command_line contains ".pdf" or action_process_image_command_line contains ".txt")) and (((action_process_image_command_line contains "dir " and action_process_image_command_line contains " /b " and action_process_image_command_line contains " /s ")) or (action_process_image_name = "FINDSTR.EXE" and (action_process_image_command_line contains " /e " or action_process_image_command_line contains " /si "))))
