// Title: ETW Trace Evasion Activity
// ID: a238b5d0-ce2d-4414-a676-7a531b3d13d6
// Status: test
// Level: high
// Author: @neu5ron, Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
// Date: 2019-03-22
// Tags: attack.stealth, attack.defense-impairment, attack.t1070, attack.t1685, car.2016-04-002
// Description: Detects command line activity that tries to clear or disable any ETW trace log which could be a sign of logging evasion.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "cl" and action_process_image_command_line contains "/Trace")) or ((action_process_image_command_line contains "clear-log" and action_process_image_command_line contains "/Trace")) or ((action_process_image_command_line contains "sl" and action_process_image_command_line contains "/e:false")) or ((action_process_image_command_line contains "set-log" and action_process_image_command_line contains "/e:false")) or ((action_process_image_command_line contains "logman" and action_process_image_command_line contains "update" and action_process_image_command_line contains "trace" and action_process_image_command_line contains "--p" and action_process_image_command_line contains "-ets")) or (action_process_image_command_line contains "Remove-EtwTraceProvider") or ((action_process_image_command_line contains "Set-EtwTraceProvider" and action_process_image_command_line contains "0x11")))
