// Title: PUA - Rclone Execution
// ID: e37db05d-d1f9-49c8-b464-cee1a4b11638
// Status: test
// Level: high
// Author: Bhabesh Raj, Sittikorn S, Aaron Greetham (@beardofbinary) - NCC Group
// Date: 2021-05-10
// Tags: attack.exfiltration, attack.t1567.002
// Description: Detects execution of RClone utility for exfiltration as used by various ransomwares strains like REvil, Conti, FiveHands, etc
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "--config " and action_process_image_command_line contains "--no-check-certificate " and action_process_image_command_line contains " copy ")) or (((action_process_image_command_line contains "pass" or action_process_image_command_line contains "user" or action_process_image_command_line contains "copy" or action_process_image_command_line contains "sync" or action_process_image_command_line contains "config" or action_process_image_command_line contains "lsd" or action_process_image_command_line contains "remote" or action_process_image_command_line contains "ls" or action_process_image_command_line contains "mega" or action_process_image_command_line contains "pcloud" or action_process_image_command_line contains "ftp" or action_process_image_command_line contains "ignore-existing" or action_process_image_command_line contains "auto-confirm" or action_process_image_command_line contains "transfers" or action_process_image_command_line contains "multi-thread-streams" or action_process_image_command_line contains "no-check-certificate ")) and ((action_process_image_path endswith "\\rclone.exe") or (Description = "Rsync for cloud storage"))))
