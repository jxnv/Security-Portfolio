// Title: MacOS Network Service Scanning
// ID: 84bae5d4-b518-4ae0-b331-6d4afd34d00f
// Status: test
// Level: low
// Author: Alejandro Ortuno, oscd.community
// Date: 2020-10-21
// Tags: attack.discovery, attack.t1046
// Description: Detects enumeration of local or remote network services.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "/nc" or action_process_image_path endswith "/netcat")) and not ((action_process_image_command_line contains "l"))) or ((action_process_image_path endswith "/nmap" or action_process_image_path endswith "/telnet")))
