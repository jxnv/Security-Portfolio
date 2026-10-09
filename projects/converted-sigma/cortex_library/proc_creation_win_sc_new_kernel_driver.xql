// Title: New Kernel Driver Via SC.EXE
// ID: 431a1fdb-4799-4f3b-91c3-a683b003fc49
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-07-14
// Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
// Description: Detects creation of a new service (kernel driver) with the type "kernel"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\sc.exe" and (action_process_image_command_line contains "create" or action_process_image_command_line contains "config") and (action_process_image_command_line contains "binPath" and action_process_image_command_line contains "type" and action_process_image_command_line contains "kernel")) and not ((((action_process_image_command_line contains "create netprotection_network_filter" and action_process_image_command_line contains "type= kernel start= " and action_process_image_command_line contains "binPath= System32\\drivers\\netprotection_network_filter" and action_process_image_command_line contains "DisplayName= netprotection_network_filter" and action_process_image_command_line contains "group= PNP_TDI tag= yes")) or ((action_process_image_command_line contains "create avelam binpath=C:\\Windows\\system32\\drivers\\avelam.sys" and action_process_image_command_line contains "type=kernel start=boot error=critical group=Early-Launch")))))
