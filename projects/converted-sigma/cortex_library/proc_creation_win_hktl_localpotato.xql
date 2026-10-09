// Title: HackTool - LocalPotato Execution
// ID: 6bd75993-9888-4f91-9404-e1e4e4e34b77
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-14
// Tags: attack.privilege-escalation, cve.2023-21746, attack.stealth
// Description: Detects the execution of the LocalPotato POC based on basic PE metadata information and default CLI examples
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains ".exe -i C:\\" and action_process_image_command_line contains "-o Windows\\")) or ((Hashes contains "IMPHASH=E1742EE971D6549E8D4D81115F88F1FC" or Hashes contains "IMPHASH=DD82066EFBA94D7556EF582F247C8BB5")) or (action_process_image_path endswith "\\LocalPotato.exe"))
