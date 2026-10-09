// Title: UAC Bypass Using EventVwr
// ID: 63e4f530-65dc-49cc-8f80-ccfa95c69d43
// Status: test
// Level: high
// Author: Antonio Cocomazzi (idea), Florian Roth (Nextron Systems)
// Date: 2022-04-27
// Tags: attack.privilege-escalation, attack.stealth
// Description: Detects the pattern of a UAC bypass using Windows Event Viewer
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith "\\Microsoft\\Event Viewer\\RecentViews" or action_file_path endswith "\\Microsoft\\EventV~1\\RecentViews")) and not (((action_process_image_path startswith "C:\\Windows\\System32\\" or action_process_image_path startswith "C:\\Windows\\SysWOW64\\"))))
