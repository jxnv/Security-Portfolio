// Title: Execute Pcwrun.EXE To Leverage Follina
// ID: 6004abd0-afa4-4557-ba90-49d172e0a299
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-13
// Tags: attack.stealth, attack.t1218, attack.execution
// Description: Detects indirect command execution via Program Compatibility Assistant "pcwrun.exe" leveraging the follina (CVE-2022-30190) vulnerability
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\pcwrun.exe" and action_process_image_command_line contains "../")
