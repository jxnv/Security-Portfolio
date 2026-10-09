// Title: Suspicious Debugger Registration Cmdline
// ID: ae215552-081e-44c7-805f-be16f975c8a2
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), oscd.community, Jonhnathan Ribeiro
// Date: 2019-09-06
// Tags: attack.persistence, attack.privilege-escalation, attack.t1546.008
// Description: Detects the registration of a debugger for a program that is available in the logon screen (sticky key backdoor).
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "\\CurrentVersion\\Image File Execution Options\\") and ((action_process_image_command_line contains "sethc.exe" or action_process_image_command_line contains "utilman.exe" or action_process_image_command_line contains "osk.exe" or action_process_image_command_line contains "magnify.exe" or action_process_image_command_line contains "narrator.exe" or action_process_image_command_line contains "displayswitch.exe" or action_process_image_command_line contains "atbroker.exe" or action_process_image_command_line contains "HelpPane.exe")))
