// Title: Renamed Plink Execution
// ID: 1c12727d-02bf-45ff-a9f3-d49806a3cf43
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-06
// Tags: attack.stealth, attack.t1036
// Description: Detects the execution of a renamed version of the Plink binary
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_name = "Plink") or ((action_process_image_command_line contains " -l forward" and action_process_image_command_line contains " -P " and action_process_image_command_line contains " -R "))) and not ((action_process_image_path endswith "\\plink.exe")))
