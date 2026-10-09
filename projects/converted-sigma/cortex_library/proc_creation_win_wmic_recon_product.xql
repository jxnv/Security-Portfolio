// Title: Potential Product Reconnaissance Via Wmic.EXE
// ID: 15434e33-5027-4914-88d5-3d4145ec25a9
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali
// Date: 2023-02-14
// Tags: attack.execution, attack.t1047
// Description: Detects the execution of WMIC in order to get a list of firewall and antivirus products
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "Product") and ((action_process_image_path endswith "\\wmic.exe") or (action_process_image_name = "wmic.exe"))) and not ((((action_process_image_command_line contains " uninstall" or action_process_image_command_line contains " install")) or (action_process_image_command_line contains "csproduct"))))
