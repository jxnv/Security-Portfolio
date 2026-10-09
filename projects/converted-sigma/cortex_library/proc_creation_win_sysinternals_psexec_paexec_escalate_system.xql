// Title: PsExec/PAExec Escalation to LOCAL SYSTEM
// ID: 8834e2f7-6b4b-4f09-8906-d2276470ee23
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-11-23
// Tags: attack.resource-development, attack.t1587.001
// Description: Detects suspicious commandline flags used by PsExec and PAExec to escalate a command line to LOCAL_SYSTEM rights
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "psexec" or action_process_image_command_line contains "paexec" or action_process_image_command_line contains "accepteula")) and ((action_process_image_command_line contains " -s cmd" or action_process_image_command_line contains " -s -i cmd" or action_process_image_command_line contains " -i -s cmd" or action_process_image_command_line contains " -s pwsh" or action_process_image_command_line contains " -s -i pwsh" or action_process_image_command_line contains " -i -s pwsh" or action_process_image_command_line contains " -s powershell" or action_process_image_command_line contains " -s -i powershell" or action_process_image_command_line contains " -i -s powershell")))
