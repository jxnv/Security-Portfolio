// Title: DumpStack.log Defender Evasion
// ID: 4f647cfa-b598-4e12-ad69-c68dd16caef8
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-06
// Tags: attack.defense-impairment
// Description: Detects the use of the filename DumpStack.log to evade Microsoft Defender
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\DumpStack.log") or (action_process_image_command_line contains " -o DumpStack.log"))
