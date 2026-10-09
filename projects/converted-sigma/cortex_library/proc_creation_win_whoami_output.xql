// Title: Whoami.EXE Execution With Output Option
// ID: c30fb093-1109-4dc8-88a8-b30d11c95a5d
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-28
// Tags: attack.discovery, attack.t1033, car.2016-03-001
// Description: Detects the execution of "whoami.exe" with the "/FO" flag to choose CSV as output format or with redirection options to export the results to a file for later use.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains " /FO CSV" or action_process_image_command_line contains " -FO CSV")) and ((action_process_image_path endswith "\\whoami.exe") or (action_process_image_name = "whoami.exe"))) or (action_process_image_command_line contains "whoami*>"))
