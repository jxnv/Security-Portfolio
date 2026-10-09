// Title: User Added To Highly Privileged Group
// ID: 10fb649c-3600-4d37-b1e6-56ea90bb7e09
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-02-23
// Tags: attack.privilege-escalation, attack.persistence, attack.t1098
// Description: Detects addition of users to highly privileged groups via "Net" or "Add-LocalGroupMember".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Group Policy Creator Owners" or action_process_image_command_line contains "Schema Admins")) and (((action_process_image_command_line contains "localgroup " and action_process_image_command_line contains " /add")) or ((action_process_image_command_line contains "Add-LocalGroupMember " and action_process_image_command_line contains " -Group "))))
