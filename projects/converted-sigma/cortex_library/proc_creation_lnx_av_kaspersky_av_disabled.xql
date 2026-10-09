// Title: Kaspersky Endpoint Security Stopped Via CommandLine - Linux
// ID: 36388120-b3f1-4ce9-b50b-280d9a7f4c04
// Status: experimental
// Level: high
// Author: Milad Cheraghi
// Date: 2025-10-18
// Tags: attack.execution, attack.defense-impairment, attack.t1685
// Description: Detects execution of the Kaspersky init.d stop script on Linux systems either directly or via systemctl.
// This activity may indicate a manual interruption of the antivirus service by an administrator, or it could be a sign of potential tampering or evasion attempts by malicious actors.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "/systemctl" or action_process_image_path endswith "/bash" or action_process_image_path endswith "/sh") and (action_process_image_command_line contains "stop" and action_process_image_command_line contains "kesl"))
