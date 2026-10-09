// Title: Potential Configuration And Service Reconnaissance Via Reg.EXE
// ID: 970007b7-ce32-49d0-a4a4-fbef016950bd
// Status: test
// Level: medium
// Author: Timur Zinniatullin, oscd.community
// Date: 2019-10-21
// Tags: attack.discovery, attack.t1012, attack.t1007
// Description: Detects the usage of "reg.exe" in order to query reconnaissance information from the registry. Adversaries may interact with the Windows registry to gather information about credentials, the system, configuration, and installed software.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "query") and ((action_process_image_path endswith "\\reg.exe") or (action_process_image_name = "reg.exe")) and ((action_process_image_command_line contains "currentVersion\\windows" or action_process_image_command_line contains "winlogon\\" or action_process_image_command_line contains "currentVersion\\shellServiceObjectDelayLoad" or action_process_image_command_line contains "currentVersion\\run" or action_process_image_command_line contains "currentVersion\\policies\\explorer\\run" or action_process_image_command_line contains "currentcontrolset\\services")))
