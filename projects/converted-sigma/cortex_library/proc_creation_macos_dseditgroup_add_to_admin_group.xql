// Title: User Added To Admin Group Via DseditGroup
// ID: 5d0fdb62-f225-42fb-8402-3dfe64da468a
// Status: test
// Level: medium
// Author: Sohan G (D4rkCiph3r)
// Date: 2023-08-22
// Tags: attack.persistence, attack.initial-access, attack.privilege-escalation, attack.stealth, attack.t1078.003
// Description: Detects attempts to create and/or add an account to the admin group, thus granting admin privileges.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/dseditgroup" and (action_process_image_command_line contains " -o edit " and action_process_image_command_line contains " -a " and action_process_image_command_line contains " -t user" and action_process_image_command_line contains "admin"))
