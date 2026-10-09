// Title: Local Network Connection Initiated By Script Interpreter
// ID: 08249dc0-a28d-4555-8ba5-9255a198e08c
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-08-28
// Tags: attack.command-and-control, attack.t1105
// Description: Detects a script interpreter (Wscript/Cscript) initiating a local network connection to download or execute a script hosted on a shared folder.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Initiated = "true" and (action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe") and (incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "10.0.0.0/8") or incidr(action_remote_ip, "172.16.0.0/12") or incidr(action_remote_ip, "192.168.0.0/16") or incidr(action_remote_ip, "169.254.0.0/16") or incidr(action_remote_ip, "::1/128") or incidr(action_remote_ip, "fe80::/10") or incidr(action_remote_ip, "fc00::/7")))
