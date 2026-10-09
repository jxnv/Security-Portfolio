// Title: Flush Iptables Ufw Chain
// ID: 3be619f4-d9ec-4ea8-a173-18fdd01996ab
// Status: test
// Level: medium
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-01-18
// Tags: attack.defense-impairment, attack.t1686
// Description: Detect use of iptables to flush all firewall rules, tables and chains and allow all network traffic
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "/iptables" or action_process_image_path endswith "/xtables-legacy-multi" or action_process_image_path endswith "/iptables-legacy-multi" or action_process_image_path endswith "/ip6tables" or action_process_image_path endswith "/ip6tables-legacy-multi")) and ((action_process_image_command_line contains "-F" or action_process_image_command_line contains "-Z" or action_process_image_command_line contains "-X")) and ((action_process_image_command_line contains "ufw-logging-deny" or action_process_image_command_line contains "ufw-logging-allow" or action_process_image_command_line contains "ufw6-logging-deny" or action_process_image_command_line contains "ufw6-logging-allow")))
