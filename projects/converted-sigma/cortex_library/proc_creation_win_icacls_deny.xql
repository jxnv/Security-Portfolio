// Title: Use Icacls to Hide File to Everyone
// ID: 4ae81040-fc1c-4249-bfa3-938d260214d9
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-07-18
// Tags: attack.stealth, attack.t1564.001
// Description: Detect use of icacls to deny access for everyone in Users folder sometimes used to hide malicious files
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "/deny" and action_process_image_command_line contains "*S-1-1-0:")) and ((action_process_image_name = "iCACLS.EXE") or (action_process_image_path endswith "\\icacls.exe")))
