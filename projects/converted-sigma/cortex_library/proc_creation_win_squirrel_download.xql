// Title: Arbitrary File Download Via Squirrel.EXE
// ID: 1e75c1cc-c5d4-42aa-ac3d-91b0b68b3b4c
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), Karneades / Markus Neis, Jonhnathan Ribeiro, oscd.community
// Date: 2022-06-09
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: Detects the usage of the "Squirrel.exe" to download arbitrary files. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " --download " or action_process_image_command_line contains " --update " or action_process_image_command_line contains " --updateRollback=")) and (action_process_image_command_line contains "http") and ((action_process_image_path endswith "\\squirrel.exe" or action_process_image_path endswith "\\update.exe")))
