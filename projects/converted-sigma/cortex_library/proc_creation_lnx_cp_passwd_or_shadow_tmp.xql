// Title: Copy Passwd Or Shadow From TMP Path
// ID: fa4aaed5-4fe0-498d-bbc0-08e3346387ba
// Status: test
// Level: high
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-01-31
// Tags: attack.credential-access, attack.t1552.001
// Description: Detects when the file "passwd" or "shadow" is copied from tmp path
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "passwd" or action_process_image_command_line contains "shadow")) and (action_process_image_path endswith "/cp") and (action_process_image_command_line contains "/tmp/"))
