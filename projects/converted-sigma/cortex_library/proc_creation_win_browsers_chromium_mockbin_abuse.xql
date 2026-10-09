// Title: Chromium Browser Headless Execution To Mockbin Like Site
// ID: 1c526788-0abe-4713-862f-b520da5e5316
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-09-11
// Tags: attack.execution
// Description: Detects the execution of a Chromium based browser process with the "headless" flag and a URL pointing to the mockbin.org service (which can be used to exfiltrate data).
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "--headless") and ((action_process_image_path endswith "\\brave.exe" or action_process_image_path endswith "\\chrome.exe" or action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\opera.exe" or action_process_image_path endswith "\\vivaldi.exe")) and ((action_process_image_command_line contains "://run.mocky" or action_process_image_command_line contains "://mockbin")))
