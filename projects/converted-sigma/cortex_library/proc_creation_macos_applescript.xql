// Title: MacOS Scripting Interpreter AppleScript
// ID: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
// Status: test
// Level: medium
// Author: Alejandro Ortuno, oscd.community
// Date: 2020-10-21
// Tags: attack.execution, attack.t1059.002
// Description: Detects execution of AppleScript of the macOS scripting language AppleScript.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/osascript" and (action_process_image_command_line contains " -e " or action_process_image_command_line contains ".scpt" or action_process_image_command_line contains ".js")) and not ((actor_process_image_path endswith "opencode" and (action_process_image_command_line contains "osascript" and action_process_image_command_line contains " -e " and action_process_image_command_line contains "set imageData to the clipboard" and action_process_image_command_line contains "set fileRef"))))
