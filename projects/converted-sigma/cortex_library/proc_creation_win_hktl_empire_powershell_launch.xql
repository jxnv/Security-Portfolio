// Title: HackTool - Empire PowerShell Launch Parameters
// ID: 79f4ede3-402e-41c8-bc3e-ebbf5f162581
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-04-20
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious powershell command line parameters used in Empire
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains " -NoP -sta -NonI -W Hidden -Enc " or action_process_image_command_line contains " -noP -sta -w 1 -enc " or action_process_image_command_line contains " -NoP -NonI -W Hidden -enc " or action_process_image_command_line contains " -noP -sta -w 1 -enc" or action_process_image_command_line contains " -enc  SQB" or action_process_image_command_line contains " -nop -exec bypass -EncodedCommand "))
