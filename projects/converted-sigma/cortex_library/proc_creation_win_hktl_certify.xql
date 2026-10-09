// Title: HackTool - Certify Execution
// ID: 762f2482-ff21-4970-8939-0aa317a886bb
// Status: test
// Level: high
// Author: pH-T (Nextron Systems)
// Date: 2023-04-17
// Tags: attack.discovery, attack.credential-access, attack.t1649
// Description: Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\Certify.exe") or (action_process_image_name = "Certify.exe") or (Description contains "Certify")) or (((action_process_image_command_line contains ".exe cas " or action_process_image_command_line contains ".exe find " or action_process_image_command_line contains ".exe pkiobjects " or action_process_image_command_line contains ".exe request " or action_process_image_command_line contains ".exe download ")) and ((action_process_image_command_line contains " /vulnerable" or action_process_image_command_line contains " /template:" or action_process_image_command_line contains " /altname:" or action_process_image_command_line contains " /domain:" or action_process_image_command_line contains " /path:" or action_process_image_command_line contains " /ca:"))))
