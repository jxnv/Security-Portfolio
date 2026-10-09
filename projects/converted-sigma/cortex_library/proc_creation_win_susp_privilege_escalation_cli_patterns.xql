// Title: Suspicious RunAs-Like Flag Combination
// ID: 50d66fb0-03f8-4da0-8add-84e77d12a020
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-11-11
// Tags: attack.privilege-escalation
// Description: Detects suspicious command line flags that let the user set a target user and command as e.g. seen in PsExec-like tools
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -c cmd" or action_process_image_command_line contains " -c \"cmd" or action_process_image_command_line contains " -c powershell" or action_process_image_command_line contains " -c \"powershell" or action_process_image_command_line contains " --command cmd" or action_process_image_command_line contains " --command powershell" or action_process_image_command_line contains " -c whoami" or action_process_image_command_line contains " -c wscript" or action_process_image_command_line contains " -c cscript")) and ((action_process_image_command_line contains " -u system " or action_process_image_command_line contains " --user system " or action_process_image_command_line contains " -u NT" or action_process_image_command_line contains " -u \"NT" or action_process_image_command_line contains " -u 'NT" or action_process_image_command_line contains " --system " or action_process_image_command_line contains " -u administrator ")))
