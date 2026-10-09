// Title: Root Certificate Installed From Susp Locations
// ID: 5f6a601c-2ecb-498b-9c33-660362323afa
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-09
// Tags: attack.defense-impairment, attack.t1553.004
// Description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "Import-Certificate" and action_process_image_command_line contains " -FilePath " and action_process_image_command_line contains "Cert:\\LocalMachine\\Root") and (action_process_image_command_line contains "\\AppData\\Local\\Temp\\" or action_process_image_command_line contains ":\\Windows\\TEMP\\" or action_process_image_command_line contains "\\Desktop\\" or action_process_image_command_line contains "\\Downloads\\" or action_process_image_command_line contains "\\Perflogs\\" or action_process_image_command_line contains ":\\Users\\Public\\"))
