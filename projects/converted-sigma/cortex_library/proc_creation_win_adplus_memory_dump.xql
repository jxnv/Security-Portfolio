// Title: Potential Adplus.EXE Abuse
// ID: 2f869d59-7f6a-4931-992c-cce556ff2d53
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-09
// Tags: attack.execution, attack.credential-access, attack.t1003.001
// Description: Detects execution of "AdPlus.exe", a binary that is part of the Windows SDK that can be used as a LOLBIN in order to dump process memory and execute arbitrary commands.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -hang " or action_process_image_command_line contains " -pn " or action_process_image_command_line contains " -pmn " or action_process_image_command_line contains " -p " or action_process_image_command_line contains " -po " or action_process_image_command_line contains " -c " or action_process_image_command_line contains " -sc ")) and ((action_process_image_path endswith "\\adplus.exe") or (action_process_image_name = "Adplus.exe")))
