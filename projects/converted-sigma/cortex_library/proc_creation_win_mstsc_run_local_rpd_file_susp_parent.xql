// Title: Mstsc.EXE Execution From Uncommon Parent
// ID: ff3b6b39-e765-42f9-bb2c-ea6761e0e0f6
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-18
// Tags: attack.lateral-movement
// Description: Detects potential RDP connection via Mstsc using a local ".rdp" file located in suspicious locations.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\mstsc.exe") or (action_process_image_name = "mstsc.exe")) and ((actor_process_image_path endswith "\\brave.exe" or actor_process_image_path endswith "\\CCleanerBrowser.exe" or actor_process_image_path endswith "\\chrome.exe" or actor_process_image_path endswith "\\chromium.exe" or actor_process_image_path endswith "\\firefox.exe" or actor_process_image_path endswith "\\iexplore.exe" or actor_process_image_path endswith "\\microsoftedge.exe" or actor_process_image_path endswith "\\msedge.exe" or actor_process_image_path endswith "\\opera.exe" or actor_process_image_path endswith "\\vivaldi.exe" or actor_process_image_path endswith "\\whale.exe" or actor_process_image_path endswith "\\outlook.exe")))
