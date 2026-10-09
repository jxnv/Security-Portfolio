// Title: System Network Discovery - macOS
// ID: 58800443-f9fc-4d55-ae0c-98a3966dfb97
// Status: test
// Level: informational
// Author: remotephone, oscd.community
// Date: 2020-10-06
// Tags: attack.discovery, attack.t1016
// Description: Detects enumeration of local network configuration
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "/arp" or action_process_image_path endswith "/ifconfig" or action_process_image_path endswith "/netstat" or action_process_image_path endswith "/networksetup" or action_process_image_path endswith "/socketfilterfw")) or (action_process_image_path = "/usr/bin/defaults" and (action_process_image_command_line contains "/Library/Preferences/com.apple.alf" and action_process_image_command_line contains "read"))) and not ((actor_process_image_path endswith "/wifivelocityd")))
