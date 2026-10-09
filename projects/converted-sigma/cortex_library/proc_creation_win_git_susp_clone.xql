// Title: Suspicious Git Clone
// ID: aef9d1f1-7396-4e92-a927-4567c7a495c1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-03
// Tags: attack.reconnaissance, attack.t1593.003
// Description: Detects execution of "git" in order to clone a remote repository that contain suspicious keywords which might be suspicious
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " clone " or action_process_image_command_line contains "git-remote-https ")) and (((action_process_image_path endswith "\\git.exe" or action_process_image_path endswith "\\git-remote-https.exe")) or (action_process_image_name = "git.exe")) and ((action_process_image_command_line contains "exploit" or action_process_image_command_line contains "Vulns" or action_process_image_command_line contains "vulnerability" or action_process_image_command_line contains "RemoteCodeExecution" or action_process_image_command_line contains "Invoke-" or action_process_image_command_line contains "CVE-" or action_process_image_command_line contains "poc-" or action_process_image_command_line contains "ProofOfConcept" or action_process_image_command_line contains "proxyshell" or action_process_image_command_line contains "log4shell" or action_process_image_command_line contains "eternalblue" or action_process_image_command_line contains "eternal-blue" or action_process_image_command_line contains "MS17-")))
