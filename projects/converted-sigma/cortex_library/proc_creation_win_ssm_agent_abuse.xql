// Title: Potential Amazon SSM Agent Hijacking
// ID: d20ee2f4-822c-4827-9e15-41500b1fff10
// Status: test
// Level: medium
// Author: Muhammad Faisal
// Date: 2023-08-02
// Tags: attack.command-and-control, attack.persistence, attack.t1219.002
// Description: Detects potential Amazon SSM agent hijack attempts as outlined in the Mitiga research report.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\amazon-ssm-agent.exe" and (action_process_image_command_line contains "-register " and action_process_image_command_line contains "-code " and action_process_image_command_line contains "-id " and action_process_image_command_line contains "-region "))
