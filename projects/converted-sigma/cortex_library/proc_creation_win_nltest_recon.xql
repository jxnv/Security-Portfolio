// Title: Potential Recon Activity Via Nltest.EXE
// ID: 5cc90652-4cbd-4241-aa3b-4b462fa5a248
// Status: test
// Level: medium
// Author: Craig Young, oscd.community, Georg Lauenstein
// Date: 2021-07-24
// Tags: attack.discovery, attack.t1016, attack.t1482
// Description: Detects nltest commands that can be used for information discovery
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_path endswith "\\nltest.exe") or (action_process_image_name = "nltestrk.exe")) and (((action_process_image_command_line contains "server" and action_process_image_command_line contains "query")) or ((action_process_image_command_line contains "/user" or action_process_image_command_line contains "all_trusts" or action_process_image_command_line contains "dclist:" or action_process_image_command_line contains "dnsgetdc:" or action_process_image_command_line contains "domain_trusts" or action_process_image_command_line contains "dsgetdc:" or action_process_image_command_line contains "parentdomain" or action_process_image_command_line contains "trusted_domains"))))
