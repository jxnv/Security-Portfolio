// Title: Modify Group Policy Settings
// ID: ada4b0c4-758b-46ac-9033-9004613a150d
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-08-19
// Tags: attack.privilege-escalation, attack.defense-impairment, attack.t1484.001
// Description: Detect malicious GPO modifications can be used to implement many other malicious behaviors.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "GroupPolicyRefreshTimeDC" or action_process_image_command_line contains "GroupPolicyRefreshTimeOffsetDC" or action_process_image_command_line contains "GroupPolicyRefreshTime" or action_process_image_command_line contains "GroupPolicyRefreshTimeOffset" or action_process_image_command_line contains "EnableSmartScreen" or action_process_image_command_line contains "ShellSmartScreenLevel")) and (action_process_image_command_line contains "\\SOFTWARE\\Policies\\Microsoft\\Windows\\System") and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe")))
