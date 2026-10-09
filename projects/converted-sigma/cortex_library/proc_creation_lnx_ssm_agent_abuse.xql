// Title: Potential Linux Amazon SSM Agent Hijacking
// ID: f9b3edc5-3322-4fc7-8aa3-245d646cc4b7
// Status: test
// Level: medium
// Author: Muhammad Faisal
// Date: 2023-08-03
// Tags: attack.command-and-control, attack.persistence, attack.t1219.002
// Description: Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/amazon-ssm-agent" and (action_process_image_command_line contains "-register " and action_process_image_command_line contains "-code " and action_process_image_command_line contains "-id " and action_process_image_command_line contains "-region "))
