// Title: Outbound Network Connection To Public IP Via Winlogon
// ID: 7610a4ea-c06d-495f-a2ac-0a696abcfd3b
// Status: test
// Level: medium
// Author: Christopher Peacock @securepeacock, SCYTHE @scythe_io
// Date: 2023-04-28
// Tags: attack.execution, attack.command-and-control, attack.stealth, attack.t1218.011
// Description: Detects a "winlogon.exe" process that initiate network communications with public IP addresses
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\winlogon.exe" and Initiated = "true") and not (((incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "10.0.0.0/8") or incidr(action_remote_ip, "172.16.0.0/12") or incidr(action_remote_ip, "192.168.0.0/16") or incidr(action_remote_ip, "169.254.0.0/16") or incidr(action_remote_ip, "::1/128") or incidr(action_remote_ip, "fe80::/10") or incidr(action_remote_ip, "fc00::/7")))))
