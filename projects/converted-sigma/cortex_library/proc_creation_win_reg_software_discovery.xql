// Title: Detected Windows Software Discovery
// ID: e13f668e-7f95-443d-98d2-1816a7648a7b
// Status: test
// Level: medium
// Author: Nikita Nazarov, oscd.community
// Date: 2020-10-16
// Tags: attack.discovery, attack.t1518
// Description: Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\reg.exe" and (action_process_image_command_line contains "query" and action_process_image_command_line contains "\\software\\" and action_process_image_command_line contains "/v" and action_process_image_command_line contains "svcversion"))
