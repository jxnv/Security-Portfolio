// Title: Gpresult Display Group Policy Information
// ID: e56d3073-83ff-4021-90fe-c658e0709e72
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-05-01
// Tags: attack.discovery, attack.t1615
// Description: Detects cases in which a user uses the built-in Windows utility gpresult to display the Resultant Set of Policy (RSoP) information
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\gpresult.exe" and (action_process_image_command_line contains "/z" or action_process_image_command_line contains "/v"))
