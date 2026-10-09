// Title: Suspicious Package Installed - Linux
// ID: 700fb7e8-2981-401c-8430-be58e189e741
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-03
// Tags: attack.defense-impairment, attack.t1553.004
// Description: Detects installation of suspicious packages using system installation utilities
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "/apt" or action_process_image_path endswith "/apt-get") and action_process_image_command_line contains "install") or (action_process_image_path endswith "/dpkg" and (action_process_image_command_line contains "--install" or action_process_image_command_line contains "-i")) or (action_process_image_path endswith "/rpm" and action_process_image_command_line contains "-i") or (action_process_image_path endswith "/yum" and (action_process_image_command_line contains "localinstall" or action_process_image_command_line contains "install"))) and ((action_process_image_command_line contains "nmap" or action_process_image_command_line contains " nc" or action_process_image_command_line contains "netcat" or action_process_image_command_line contains "wireshark" or action_process_image_command_line contains "tshark" or action_process_image_command_line contains "openconnect" or action_process_image_command_line contains "proxychains" or action_process_image_command_line contains "socat")))
