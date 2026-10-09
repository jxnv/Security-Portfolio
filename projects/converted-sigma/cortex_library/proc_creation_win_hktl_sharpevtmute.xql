// Title: HackTool - SharpEvtMute Execution
// ID: bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-09-07
// Tags: attack.defense-impairment, attack.t1685.001
// Description: Detects the use of SharpEvtHook, a tool that tampers with the Windows event logs
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\SharpEvtMute.exe") or (Description = "SharpEvtMute") or ((action_process_image_command_line contains "--Filter \"rule " or action_process_image_command_line contains "--Encoded --Filter \\\"")))
