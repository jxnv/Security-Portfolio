// Title: Suspicious Wordpad Outbound Connections
// ID: 786cdae8-fefb-4eb2-9227-04e34060db01
// Status: test
// Level: medium
// Author: X__Junior (Nextron Systems)
// Date: 2023-07-12
// Tags: attack.command-and-control, attack.stealth
// Description: Detects a network connection initiated by "wordpad.exe" over uncommon destination ports.
// This might indicate potential process injection activity from a beacon or similar mechanisms.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Initiated = "true" and action_process_image_path endswith "\\wordpad.exe") and not (((action_remote_port = 80 or action_remote_port = 139 or action_remote_port = 443 or action_remote_port = 445 or action_remote_port = 465 or action_remote_port = 587 or action_remote_port = 993 or action_remote_port = 995))))
