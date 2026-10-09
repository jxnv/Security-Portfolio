// Title: Potentially Suspicious Usage Of Qemu
// ID: 5fc297ae-25b6-488a-8f25-cc12ac29b744
// Status: test
// Level: medium
// Author: Muhammad Faisal (@faisalusuf), Hunter Juhan (@threatHNTR)
// Date: 2024-06-03
// Tags: attack.command-and-control, attack.t1090, attack.t1572
// Description: Detects potentially suspicious execution of the Qemu utility in a Windows environment.
// Threat actors have leveraged this utility and this technique for achieving network access as reported by Kaspersky.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-m 1M" or action_process_image_command_line contains "-m 2M" or action_process_image_command_line contains "-m 3M") and (action_process_image_command_line contains "restrict=off" and action_process_image_command_line contains "-netdev " and action_process_image_command_line contains "connect=" and action_process_image_command_line contains "-nographic")) and not (((action_process_image_command_line contains " -cdrom " or action_process_image_command_line contains " type=virt " or action_process_image_command_line contains " -blockdev "))))
