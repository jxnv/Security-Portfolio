// Title: RegAsm.EXE Initiating Network Connection To Public IP
// ID: 0531e43a-d77d-47c2-b89f-5fe50321c805
// Status: test
// Level: medium
// Author: frack113
// Date: 2024-04-25
// Tags: attack.stealth, attack.t1218.009
// Description: Detects "RegAsm.exe" initiating a network connection to public IP adresses
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Initiated = "true" and action_process_image_path endswith "\\regasm.exe") and not (((incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "10.0.0.0/8") or incidr(action_remote_ip, "172.16.0.0/12") or incidr(action_remote_ip, "192.168.0.0/16") or incidr(action_remote_ip, "169.254.0.0/16") or incidr(action_remote_ip, "::1/128") or incidr(action_remote_ip, "fe80::/10") or incidr(action_remote_ip, "fc00::/7")))))
