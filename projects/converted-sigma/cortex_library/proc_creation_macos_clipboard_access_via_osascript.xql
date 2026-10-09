// Title: Clipboard Access Via OSAScript
// ID: 7794fa3c-edea-4cff-bec7-267dd4770fd7
// Status: test
// Level: medium
// Author: Sohan G (D4rkCiph3r)
// Date: 2023-01-31
// Tags: attack.collection, attack.execution, attack.t1115, attack.t1059.002
// Description: Detects access to clipboard content via osascript, which may be used for data collection but also occurs in legitimate clipboard utilities and automation scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/osascript" and (action_process_image_command_line contains " -e " and action_process_image_command_line contains "clipboard")) and not ((actor_process_image_path endswith "opencode" and (action_process_image_command_line contains "osascript" and action_process_image_command_line contains " -e " and action_process_image_command_line contains "set imageData to the clipboard" and action_process_image_command_line contains "set fileRef"))))
