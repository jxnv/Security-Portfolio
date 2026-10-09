// Title: HackTool - SharpImpersonation Execution
// ID: f89b08d0-77ad-4728-817b-9b16c5a69c7a
// Status: test
// Level: high
// Author: Sai Prashanth Pulisetti @pulisettis, Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-27
// Tags: attack.privilege-escalation, attack.stealth, attack.t1134.001, attack.t1134.003
// Description: Detects execution of the SharpImpersonation tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " user:" and action_process_image_command_line contains " binary:")) or ((action_process_image_command_line contains " user:" and action_process_image_command_line contains " shellcode:")) or ((action_process_image_command_line contains " technique:CreateProcessAsUserW" or action_process_image_command_line contains " technique:ImpersonateLoggedOnuser"))) or ((action_process_image_path endswith "\\SharpImpersonation.exe") or (action_process_image_name = "SharpImpersonation.exe")))
