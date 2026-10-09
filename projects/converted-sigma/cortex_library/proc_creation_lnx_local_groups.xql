// Title: Local Groups Discovery - Linux
// ID: 676381a6-15ca-4d73-a9c8-6a22e970b90d
// Status: test
// Level: low
// Author: Ömer Günal, Alejandro Ortuno, oscd.community
// Date: 2020-10-11
// Tags: attack.discovery, attack.t1069.001
// Description: Detects enumeration of local system groups. Adversaries may attempt to find local system groups and permission settings
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/groups") or ((action_process_image_path endswith "/cat" or action_process_image_path endswith "/ed" or action_process_image_path endswith "/head" or action_process_image_path endswith "/less" or action_process_image_path endswith "/more" or action_process_image_path endswith "/nano" or action_process_image_path endswith "/tail" or action_process_image_path endswith "/vi" or action_process_image_path endswith "/vim") and action_process_image_command_line contains "/etc/group"))
