// Title: System Network Discovery - Linux
// ID: e7bd1cfa-b446-4c88-8afb-403bcd79e3fa
// Status: test
// Level: informational
// Author: Ömer Günal and remotephone, oscd.community
// Date: 2020-10-06
// Tags: attack.discovery, attack.t1016
// Description: Detects enumeration of local network configuration
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "/etc/resolv.conf") or ((action_process_image_path endswith "/firewall-cmd" or action_process_image_path endswith "/ufw" or action_process_image_path endswith "/iptables" or action_process_image_path endswith "/netstat" or action_process_image_path endswith "/ss" or action_process_image_path endswith "/ip" or action_process_image_path endswith "/ifconfig" or action_process_image_path endswith "/systemd-resolve" or action_process_image_path endswith "/route")))
