// Title: HackTool - CrackMapExec Execution Patterns
// ID: 058f4380-962d-40a5-afce-50207d36d7e2
// Status: stable
// Level: high
// Author: Thomas Patzke
// Date: 2020-05-22
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1047, attack.t1053, attack.t1059.003, attack.t1059.001, attack.s0106
// Description: Detects various execution patterns of the CrackMapExec pentesting framework
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "cmd.exe /Q /c * 1> \\\\\\\\*\\\\*\\\\* 2>&1" or action_process_image_command_line contains "cmd.exe /C * > \\\\\\\\*\\\\*\\\\* 2>&1" or action_process_image_command_line contains "cmd.exe /C * > *\\\\Temp\\\\* 2>&1" or action_process_image_command_line contains "powershell.exe -exec bypass -noni -nop -w 1 -C \"" or action_process_image_command_line contains "powershell.exe -noni -nop -w 1 -enc "))
