// Title: Renamed Microsoft Teams Execution
// ID: 88f46b67-14d4-4f45-ac2c-d66984f22191
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-07-12
// Tags: attack.stealth
// Description: Detects the execution of a renamed Microsoft Teams binary.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_name = "msteams.exe" or action_process_image_name = "teams.exe")) and not (((action_process_image_path endswith "\\msteams.exe" or action_process_image_path endswith "\\teams.exe"))))
