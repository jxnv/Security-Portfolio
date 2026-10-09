// Title: HackTool - Inveigh Execution
// ID: b99a1518-1ad5-4f65-bc95-1ffff97a8fd0
// Status: test
// Level: critical
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-24
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects the use of Inveigh a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\Inveigh.exe") or ((action_process_image_name = "\\Inveigh.exe" or action_process_image_name = "\\Inveigh.dll")) or (Description = "Inveigh") or ((action_process_image_command_line contains " -SpooferIP" or action_process_image_command_line contains " -ReplyToIPs " or action_process_image_command_line contains " -ReplyToDomains " or action_process_image_command_line contains " -ReplyToMACs " or action_process_image_command_line contains " -SnifferIP")))
