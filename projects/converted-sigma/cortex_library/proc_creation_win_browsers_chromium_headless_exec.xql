// Title: Browser Execution In Headless Mode
// ID: ef9dcfed-690c-4c5d-a9d1-482cd422225c
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-09-12
// Tags: attack.command-and-control, attack.stealth, attack.t1105, attack.t1564.003
// Description: Detects execution of Chromium based browser in headless mode
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\brave.exe" or action_process_image_path endswith "\\chrome.exe" or action_process_image_path endswith "\\msedge.exe" or action_process_image_path endswith "\\opera.exe" or action_process_image_path endswith "\\vivaldi.exe") and action_process_image_command_line contains "--headless")
