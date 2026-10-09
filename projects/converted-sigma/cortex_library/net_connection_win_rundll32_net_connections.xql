// Title: Rundll32 Internet Connection
// ID: cdc8da7d-c303-42f8-b08c-b4ab47230263
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2017-11-04
// Tags: attack.stealth, attack.t1218.011, attack.execution
// Description: Detects a rundll32 that communicates with public IP addresses
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\rundll32.exe" and Initiated = "true") and not (((action_process_image_command_line endswith "\\system32\\PcaSvc.dll,PcaPatchSdbTask") or (SourceHostname endswith ".internal.cloudapp.net") or ((incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "10.0.0.0/8") or incidr(action_remote_ip, "172.16.0.0/12") or incidr(action_remote_ip, "192.168.0.0/16") or incidr(action_remote_ip, "169.254.0.0/16") or incidr(action_remote_ip, "::1/128") or incidr(action_remote_ip, "fe80::/10") or incidr(action_remote_ip, "fc00::/7"))) or ((incidr(action_remote_ip, "20.0.0.0/8") or incidr(action_remote_ip, "51.103.0.0/16") or incidr(action_remote_ip, "51.104.0.0/16") or incidr(action_remote_ip, "51.105.0.0/16"))) or (actor_process_image_path = "C:\\Windows\\System32\\svchost.exe" and action_remote_port = 443))))
