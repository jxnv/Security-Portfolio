// Title: Suspicious Windows Trace ETW Session Tamper Via Logman.EXE
// ID: cd1f961e-0b96-436b-b7c6-38da4583ec00
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-02-11
// Tags: attack.defense-impairment, attack.t1685, attack.t1685.005
// Description: Detects the execution of "logman" utility in order to disable or delete Windows trace sessions
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "stop " or action_process_image_command_line contains "delete ")) and ((action_process_image_path endswith "\\logman.exe") or (action_process_image_name = "Logman.exe")) and ((action_process_image_command_line contains "Circular Kernel Context Logger" or action_process_image_command_line contains "EventLog-" or action_process_image_command_line contains "SYSMON TRACE" or action_process_image_command_line contains "SysmonDnsEtwSession")))
