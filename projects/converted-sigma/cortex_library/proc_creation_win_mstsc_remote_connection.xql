// Title: New Remote Desktop Connection Initiated Via Mstsc.EXE
// ID: 954f0af7-62dd-418f-b3df-a84bc2c7a774
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-07
// Tags: attack.lateral-movement, attack.t1021.001
// Description: Detects the usage of "mstsc.exe" with the "/v" flag to initiate a connection to a remote server.
// Adversaries may use valid accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " /v:") and ((action_process_image_path endswith "\\mstsc.exe") or (action_process_image_name = "mstsc.exe"))) and not ((actor_process_image_path = "C:\\Windows\\System32\\lxss\\wslhost.exe" and action_process_image_command_line contains "C:\\ProgramData\\Microsoft\\WSL\\wslg.rdp")))
