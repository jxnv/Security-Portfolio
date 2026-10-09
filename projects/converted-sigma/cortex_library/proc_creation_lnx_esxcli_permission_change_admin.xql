// Title: ESXi Admin Permission Assigned To Account Via ESXCLI
// ID: 9691f58d-92c1-4416-8bf3-2edd753ec9cf
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-09-04
// Tags: attack.persistence, attack.execution, attack.privilege-escalation, attack.t1059.012, attack.t1098
// Description: Detects execution of the "esxcli" command with the "system" and "permission" flags in order to assign admin permissions to an account.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/esxcli" and action_process_image_command_line contains "system" and (action_process_image_command_line contains " permission " and action_process_image_command_line contains " set" and action_process_image_command_line contains "Admin"))
