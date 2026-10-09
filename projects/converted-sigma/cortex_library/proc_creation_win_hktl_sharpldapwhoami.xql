// Title: HackTool - SharpLdapWhoami Execution
// ID: d9367cbb-c2e0-47ce-bdc0-128cb6da898d
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-08-29
// Tags: attack.discovery, attack.t1033, car.2016-03-001
// Description: Detects SharpLdapWhoami, a whoami alternative that queries the LDAP service on a domain controller
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line endswith " /method:ntlm" or action_process_image_command_line endswith " /method:kerb" or action_process_image_command_line endswith " /method:nego" or action_process_image_command_line endswith " /m:nego" or action_process_image_command_line endswith " /m:ntlm" or action_process_image_command_line endswith " /m:kerb")) or (action_process_image_path endswith "\\SharpLdapWhoami.exe") or ((action_process_image_name contains "SharpLdapWhoami") or (Product = "SharpLdapWhoami")))
