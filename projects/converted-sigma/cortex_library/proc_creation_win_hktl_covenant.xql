// Title: HackTool - Covenant PowerShell Launcher
// ID: c260b6db-48ba-4b4a-a76f-2f67644e99d2
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
// Date: 2020-06-04
// Tags: attack.execution, attack.stealth, attack.t1059.001, attack.t1564.003
// Description: Detects suspicious command lines used in Covenant luanchers
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "-Sta" and action_process_image_command_line contains "-Nop" and action_process_image_command_line contains "-Window" and action_process_image_command_line contains "Hidden") and (action_process_image_command_line contains "-Command" or action_process_image_command_line contains "-EncodedCommand")) or ((action_process_image_command_line contains "sv o (New-Object IO.MemorySteam);sv d " or action_process_image_command_line contains "mshta file.hta" or action_process_image_command_line contains "GruntHTTP" or action_process_image_command_line contains "-EncodedCommand cwB2ACAAbwAgA")))
