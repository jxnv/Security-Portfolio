// Title: System Information Discovery Via Sysctl - MacOS
// ID: 6ff08e55-ea53-4f27-94a1-eff92e6d9d5c
// Status: test
// Level: medium
// Author: Pratinav Chandra
// Date: 2024-05-27
// Tags: attack.stealth, attack.t1497.001, attack.discovery, attack.t1082
// Description: Detects the execution of "sysctl" with specific arguments that have been used by threat actors and malware. It provides system hardware information.
// This process is primarily used to detect and avoid virtualization and analysis environments.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "hw." or action_process_image_command_line contains "kern." or action_process_image_command_line contains "machdep.")) and ((action_process_image_path endswith "/sysctl") or (action_process_image_command_line contains "sysctl")))
