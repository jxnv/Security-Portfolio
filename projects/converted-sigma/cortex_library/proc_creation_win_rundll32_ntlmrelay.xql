// Title: Suspicious NTLM Authentication on the Printer Spooler Service
// ID: bb76d96b-821c-47cf-944b-7ce377864492
// Status: test
// Level: high
// Author: Elastic (idea), Tobias Michalski (Nextron Systems)
// Date: 2022-05-04
// Tags: attack.privilege-escalation, attack.credential-access, attack.t1212
// Description: Detects a privilege elevation attempt by coercing NTLM authentication on the Printer Spooler service
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains "C:\\windows\\system32\\davclnt.dll,DavSetCookie" and action_process_image_command_line contains "http") and (action_process_image_command_line contains "spoolss" or action_process_image_command_line contains "srvsvc" or action_process_image_command_line contains "/print/pipe/")) and ((action_process_image_path endswith "\\rundll32.exe") or (action_process_image_name = "RUNDLL32.EXE")))
