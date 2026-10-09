// Title: Remote Access Tool - RURAT Execution From Unusual Location
// ID: e01fa958-6893-41d4-ae03-182477c5e77d
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-19
// Tags: attack.stealth
// Description: Detects execution of Remote Utilities RAT (RURAT) from an unusual location (outside of 'C:\Program Files')
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_path endswith "\\rutserv.exe" or action_process_image_path endswith "\\rfusclient.exe")) or (Product = "Remote Utilities")) and not (((action_process_image_path startswith "C:\\Program Files\\Remote Utilities" or action_process_image_path startswith "C:\\Program Files (x86)\\Remote Utilities"))))
