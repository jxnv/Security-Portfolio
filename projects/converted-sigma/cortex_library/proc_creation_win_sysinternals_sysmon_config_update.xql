// Title: Sysmon Configuration Update
// ID: 87911521-7098-470b-a459-9a57fc80bdfd
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-09
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects updates to Sysmon's configuration. Attackers might update or replace the Sysmon configuration with a bare bone one to avoid monitoring without shutting down the service completely
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-c" or action_process_image_command_line contains "/c")) and (((action_process_image_path endswith "\\Sysmon64.exe" or action_process_image_path endswith "\\Sysmon64a.exe" or action_process_image_path endswith "\\Sysmon.exe")) or (Description = "System activity monitor")))
