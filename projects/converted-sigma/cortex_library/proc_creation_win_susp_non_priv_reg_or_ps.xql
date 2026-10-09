// Title: Non-privileged Usage of Reg or Powershell
// ID: 8f02c935-effe-45b3-8fc9-ef8696a9e41d
// Status: test
// Level: high
// Author: Teymur Kheirkhabarov (idea), Ryan Plas (rule), oscd.community
// Date: 2020-10-05
// Tags: attack.persistence, attack.defense-impairment, attack.t1112
// Description: Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "reg " and action_process_image_command_line contains "add")) or ((action_process_image_command_line contains "powershell" or action_process_image_command_line contains "set-itemproperty" or action_process_image_command_line contains " sp " or action_process_image_command_line contains "new-itemproperty"))) and ((IntegrityLevel = "Medium" or IntegrityLevel = "S-1-16-8192") and (action_process_image_command_line contains "ControlSet" and action_process_image_command_line contains "Services") and (action_process_image_command_line contains "ImagePath" or action_process_image_command_line contains "FailureCommand" or action_process_image_command_line contains "ServiceDLL")))
