// Title: Suspicious Git Clone - Linux
// ID: cfec9d29-64ec-4a0f-9ffe-0fdb856d5446
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-03
// Tags: attack.reconnaissance, attack.t1593.003
// Description: Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/git" and action_process_image_command_line contains " clone ") and ((action_process_image_command_line contains "exploit" or action_process_image_command_line contains "Vulns" or action_process_image_command_line contains "vulnerability" or action_process_image_command_line contains "RCE" or action_process_image_command_line contains "RemoteCodeExecution" or action_process_image_command_line contains "Invoke-" or action_process_image_command_line contains "CVE-" or action_process_image_command_line contains "poc-" or action_process_image_command_line contains "ProofOfConcept" or action_process_image_command_line contains "proxyshell" or action_process_image_command_line contains "log4shell" or action_process_image_command_line contains "eternalblue" or action_process_image_command_line contains "eternal-blue" or action_process_image_command_line contains "MS17-")))
