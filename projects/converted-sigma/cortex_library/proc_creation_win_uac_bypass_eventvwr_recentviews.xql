// Title: UAC Bypass Using Event Viewer RecentViews
// ID: 30fc8de7-d833-40c4-96b6-28319fbc4f6c
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-11-22
// Tags: attack.privilege-escalation, attack.stealth
// Description: Detects the pattern of UAC Bypass using Event Viewer RecentViews
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "\\Event Viewer\\RecentViews" or action_process_image_command_line contains "\\EventV~1\\RecentViews")) and (action_process_image_command_line contains ">"))
