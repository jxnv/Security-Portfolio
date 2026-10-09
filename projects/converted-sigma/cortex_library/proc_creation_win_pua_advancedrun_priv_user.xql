// Title: PUA - AdvancedRun Suspicious Execution
// ID: fa00b701-44c6-4679-994d-5a18afa8a707
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-20
// Tags: attack.privilege-escalation, attack.stealth, attack.t1134.002
// Description: Detects the execution of AdvancedRun utility in the context of the TrustedInstaller, SYSTEM, Local Service or Network Service accounts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/EXEFilename" or action_process_image_command_line contains "/CommandLine")) and (((action_process_image_command_line contains " /RunAs 8 " or action_process_image_command_line contains " /RunAs 4 " or action_process_image_command_line contains " /RunAs 10 " or action_process_image_command_line contains " /RunAs 11 ")) or ((action_process_image_command_line endswith "/RunAs 8" or action_process_image_command_line endswith "/RunAs 4" or action_process_image_command_line endswith "/RunAs 10" or action_process_image_command_line endswith "/RunAs 11"))))
