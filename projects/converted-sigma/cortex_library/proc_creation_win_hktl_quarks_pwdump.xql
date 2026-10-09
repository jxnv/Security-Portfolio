// Title: HackTool - Quarks PwDump Execution
// ID: 0685b176-c816-4837-8e7b-1216f346636b
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-05
// Tags: attack.credential-access, attack.t1003.002
// Description: Detects usage of the Quarks PwDump tool via commandline arguments
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line = " -dhl" or action_process_image_command_line = " --dump-hash-local" or action_process_image_command_line = " -dhdc" or action_process_image_command_line = " --dump-hash-domain-cached" or action_process_image_command_line = " --dump-bitlocker" or action_process_image_command_line = " -dhd " or action_process_image_command_line = " --dump-hash-domain " or action_process_image_command_line = "--ntds-file")) or (action_process_image_path endswith "\\QuarksPwDump.exe"))
