// Title: Suspicious Extrac32 Alternate Data Stream Execution
// ID: 4b13db67-0c45-40f1-aba8-66a1a7198a1e
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-11-26
// Tags: attack.stealth, attack.t1564.004
// Description: Extract data from cab file and hide it in an alternate data stream
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "extrac32.exe" and action_process_image_command_line contains ".cab") and action_process_image_command_line ~= ":[^\\\\]")
