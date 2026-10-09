// Title: PUA - RunXCmd Execution
// ID: 93199800-b52a-4dec-b762-75212c196542
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-24
// Tags: attack.execution, attack.t1569.002, attack.s0029
// Description: Detects the use of the RunXCmd tool to execute commands with System or TrustedInstaller accounts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " /account=system " or action_process_image_command_line contains " /account=ti ")) and (action_process_image_command_line contains "/exec="))
