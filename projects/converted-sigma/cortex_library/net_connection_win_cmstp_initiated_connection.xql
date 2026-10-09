// Title: Outbound Network Connection Initiated By Cmstp.EXE
// ID: efafe0bf-4238-479e-af8f-797bd3490d2d
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-30
// Tags: attack.stealth, attack.t1218.003
// Description: Detects a network connection initiated by Cmstp.EXE
// Its uncommon for "cmstp.exe" to initiate an outbound network connection. Investigate the source of such requests to determine if they are malicious.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\cmstp.exe" and Initiated = "true") and not (((incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "10.0.0.0/8") or incidr(action_remote_ip, "172.16.0.0/12") or incidr(action_remote_ip, "192.168.0.0/16") or incidr(action_remote_ip, "169.254.0.0/16") or incidr(action_remote_ip, "::1/128") or incidr(action_remote_ip, "fe80::/10") or incidr(action_remote_ip, "fc00::/7")))))
