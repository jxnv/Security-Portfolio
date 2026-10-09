// Title: Suspicious IIS URL GlobalRules Rewrite Via AppCmd
// ID: 7c8af9b2-dcae-41a2-a9db-b28c288b5f08
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-22
// Tags: attack.stealth
// Description: Detects usage of "appcmd" to create new global URL rewrite rules. This behaviour has been observed being used by threat actors to add new rules so they can access their webshells.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "set" and action_process_image_command_line contains "config" and action_process_image_command_line contains "section:system.webServer/rewrite/globalRules" and action_process_image_command_line contains "commit:")) and ((action_process_image_path endswith "\\appcmd.exe") or (action_process_image_name = "appcmd.exe")))
