// Title: Potential Privilege Escalation via Service Permissions Weakness
// ID: 0f9c21f1-6a73-4b0e-9809-cb562cb8d981
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov
// Date: 2019-10-26
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.011
// Description: Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((IntegrityLevel = "Medium" or IntegrityLevel = "S-1-16-8192") and (action_process_image_command_line contains "ControlSet" and action_process_image_command_line contains "services") and (action_process_image_command_line contains "\\ImagePath" or action_process_image_command_line contains "\\FailureCommand" or action_process_image_command_line contains "\\ServiceDll"))
