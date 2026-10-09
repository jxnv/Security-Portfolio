// Title: Console CodePage Lookup Via CHCP
// ID: 7090adee-82e2-4269-bd59-80691e7c6338
// Status: test
// Level: medium
// Author: _pete_0, TheDFIRReport
// Date: 2022-02-21
// Tags: attack.discovery, attack.t1614.001
// Description: Detects use of chcp to look up the system locale value as part of host discovery
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\cmd.exe" and (actor_process_command_line contains " -c " or actor_process_command_line contains " -r " or actor_process_command_line contains " -k ") and action_process_image_path endswith "\\chcp.com" and (action_process_image_command_line endswith "chcp" or action_process_image_command_line endswith "chcp " or action_process_image_command_line endswith "chcp  "))
