// Title: HackTool - SharpUp PrivEsc Tool Execution
// ID: c484e533-ee16-4a93-b6ac-f0ea4868b2f1
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2022-08-20
// Tags: attack.persistence, attack.privilege-escalation, attack.discovery, attack.execution, attack.stealth, attack.t1615, attack.t1569.002, attack.t1574.005
// Description: Detects the use of SharpUp, a tool for local privilege escalation
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\SharpUp.exe") or (Description = "SharpUp") or ((action_process_image_command_line contains "HijackablePaths" or action_process_image_command_line contains "UnquotedServicePath" or action_process_image_command_line contains "ProcessDLLHijack" or action_process_image_command_line contains "ModifiableServiceBinaries" or action_process_image_command_line contains "ModifiableScheduledTask" or action_process_image_command_line contains "DomainGPPPassword" or action_process_image_command_line contains "CachedGPPPassword")))
