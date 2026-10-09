// Title: HackTool - SharpLDAPmonitor Execution
// ID: 9f8fc146-1d1a-4dbf-b8fd-dfae15e08541
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-30
// Tags: attack.discovery
// Description: Detects execution of the SharpLDAPmonitor. Which can monitor the creation, deletion and changes to LDAP objects.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/user:" and action_process_image_command_line contains "/pass:" and action_process_image_command_line contains "/dcip:")) or ((action_process_image_path endswith "\\SharpLDAPmonitor.exe") or (action_process_image_name = "SharpLDAPmonitor.exe")))
