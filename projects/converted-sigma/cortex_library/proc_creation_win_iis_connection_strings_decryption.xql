// Title: Microsoft IIS Connection Strings Decryption
// ID: 97dbf6e2-e436-44d8-abee-4261b24d3e41
// Status: test
// Level: high
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-28
// Tags: attack.credential-access, attack.t1003
// Description: Detects use of aspnet_regiis to decrypt Microsoft IIS connection strings. An attacker with Microsoft IIS web server access via a webshell or alike can decrypt and dump any hardcoded connection strings, such as the MSSQL service account password using aspnet_regiis command.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "connectionStrings" and action_process_image_command_line contains " -pdf")) and ((action_process_image_path endswith "\\aspnet_regiis.exe") or (action_process_image_name = "aspnet_regiis.exe")))
