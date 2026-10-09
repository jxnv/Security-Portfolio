// Title: Capture Credentials with Rpcping.exe
// ID: 93671f99-04eb-4ab4-a161-70d446a84003
// Status: test
// Level: medium
// Author: Julia Fomina, oscd.community
// Date: 2020-10-09
// Tags: attack.credential-access, attack.t1003
// Description: Detects using Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((((action_process_image_command_line contains "-s" or action_process_image_command_line contains "/s")) and ((action_process_image_path endswith "\\RpcPing.exe") or (action_process_image_name = "\\RpcPing.exe"))) and (((action_process_image_command_line contains "-t" or action_process_image_command_line contains "/t") and action_process_image_command_line contains "ncacn_np") or ((action_process_image_command_line contains "-u" or action_process_image_command_line contains "/u") and action_process_image_command_line contains "NTLM")))
