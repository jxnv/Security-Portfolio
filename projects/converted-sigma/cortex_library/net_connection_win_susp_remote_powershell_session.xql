// Title: Potential Remote PowerShell Session Initiated
// ID: c539afac-c12a-46ed-b1bd-5a5567c9f045
// Status: test
// Level: high
// Author: Roberto Rodriguez @Cyb3rWard0g
// Date: 2019-09-12
// Tags: attack.execution, attack.t1059.001, attack.lateral-movement, attack.t1021.006
// Description: Detects a process that initiated a network connection over ports 5985 or 5986 from a non-network service account.
// This could potentially indicates a remote PowerShell connection.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_remote_port = 5985 or action_remote_port = 5986) and Initiated = "true" and SourceIsIpv6 = "false") and not ((((action_local_ip = "::1" or action_local_ip = "127.0.0.1") and (action_remote_ip = "::1" or action_remote_ip = "127.0.0.1")) or (((action_process_username contains "NETWORK SERVICE" or action_process_username contains "NETZWERKDIENST" or action_process_username contains "SERVICIO DE RED" or action_process_username contains "SERVIZIO DI RETE")) or ((action_process_username contains "SERVICE R" and action_process_username contains "SEAU"))))) and not (((action_process_image_path = "C:\\Program Files\\Avast Software\\Avast\\AvastSvc.exe" or action_process_image_path = "C:\\Program Files (x86)\\Avast Software\\Avast\\AvastSvc.exe"))))
