// Title: Security Tools Keyword Lookup Via Findstr.EXE
// ID: 4fe074b4-b833-4081-8f24-7dcfeca72b42
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), frack113
// Date: 2023-10-20
// Tags: attack.discovery, attack.t1518.001
// Description: Detects execution of "findstr" to search for common names of security tools. Attackers often pipe the results of recon commands such as "tasklist" or "whoami" to "findstr" in order to filter out the results.
// This detection focuses on the keywords that the attacker might use as a filter.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line endswith " avira" or action_process_image_command_line endswith " avira\"" or action_process_image_command_line endswith " cb" or action_process_image_command_line endswith " cb\"" or action_process_image_command_line endswith " cylance" or action_process_image_command_line endswith " cylance\"" or action_process_image_command_line endswith " defender" or action_process_image_command_line endswith " defender\"" or action_process_image_command_line endswith " kaspersky" or action_process_image_command_line endswith " kaspersky\"" or action_process_image_command_line endswith " kes" or action_process_image_command_line endswith " kes\"" or action_process_image_command_line endswith " mc" or action_process_image_command_line endswith " mc\"" or action_process_image_command_line endswith " sec" or action_process_image_command_line endswith " sec\"" or action_process_image_command_line endswith " sentinel" or action_process_image_command_line endswith " sentinel\"" or action_process_image_command_line endswith " symantec" or action_process_image_command_line endswith " symantec\"" or action_process_image_command_line endswith " virus" or action_process_image_command_line endswith " virus\"")) and (((action_process_image_path endswith "\\find.exe" or action_process_image_path endswith "\\findstr.exe")) or ((action_process_image_name = "FIND.EXE" or action_process_image_name = "FINDSTR.EXE"))))
