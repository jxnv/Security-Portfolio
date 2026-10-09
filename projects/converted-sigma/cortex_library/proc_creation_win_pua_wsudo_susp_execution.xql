// Title: PUA - Wsudo Suspicious Execution
// ID: bdeeabc9-ff2a-4a51-be59-bb253aac7891
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-02
// Tags: attack.execution, attack.privilege-escalation, attack.t1059
// Description: Detects usage of wsudo (Windows Sudo Utility). Which is a tool that let the user execute programs with different permissions (System, Trusted Installer, Administrator...etc)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-u System" or action_process_image_command_line contains "-uSystem" or action_process_image_command_line contains "-u TrustedInstaller" or action_process_image_command_line contains "-uTrustedInstaller" or action_process_image_command_line contains " --ti ")) or ((action_process_image_path endswith "\\wsudo.exe") or (action_process_image_name = "wsudo.exe") or (Description = "Windows sudo utility") or (actor_process_image_path endswith "\\wsudo-bridge.exe")))
