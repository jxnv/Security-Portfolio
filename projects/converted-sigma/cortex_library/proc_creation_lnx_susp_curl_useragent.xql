// Title: Suspicious Curl Change User Agents - Linux
// ID: b86d356d-6093-443d-971c-9b07db583c68
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-15
// Tags: attack.command-and-control, attack.t1071.001
// Description: Detects a suspicious curl process start on linux with set useragent options
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "/curl" and (action_process_image_command_line contains " -A " or action_process_image_command_line contains " --user-agent "))
