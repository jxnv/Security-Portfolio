// Title: HackTool - WinRM Access Via Evil-WinRM
// ID: a197e378-d31b-41c0-9635-cfdf1c1bb423
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-07
// Tags: attack.lateral-movement, attack.t1021.006
// Description: Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\ruby.exe" and (action_process_image_command_line contains "-i " and action_process_image_command_line contains "-u " and action_process_image_command_line contains "-p "))
