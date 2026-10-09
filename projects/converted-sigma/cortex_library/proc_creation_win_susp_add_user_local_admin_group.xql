// Title: User Added to Local Administrators Group
// ID: ad720b90-25ad-43ff-9b5e-5c841facc8e5
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-12
// Tags: attack.privilege-escalation, attack.persistence, attack.t1098
// Description: Detects addition of users to the local administrator group via "Net" or "Add-LocalGroupMember".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " administrators " or action_process_image_command_line contains " administrateur")) and (((action_process_image_command_line contains "localgroup " and action_process_image_command_line contains " /add")) or ((action_process_image_command_line contains "Add-LocalGroupMember " and action_process_image_command_line contains " -Group "))))
