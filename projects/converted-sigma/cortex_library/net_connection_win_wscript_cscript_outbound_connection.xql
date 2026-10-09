// Title: Outbound Network Connection Initiated By Script Interpreter
// ID: 992a6cae-db6a-43c8-9cec-76d7195c96fc
// Status: test
// Level: high
// Author: frack113, Florian Roth (Nextron Systems)
// Date: 2022-08-28
// Tags: attack.command-and-control, attack.t1105
// Description: Detects a script interpreter wscript/cscript opening a network connection to a non-local network. Adversaries may use script to download malicious payloads.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Initiated = "true" and (action_process_image_path endswith "\\wscript.exe" or action_process_image_path endswith "\\cscript.exe")) and not ((((incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "10.0.0.0/8") or incidr(action_remote_ip, "172.16.0.0/12") or incidr(action_remote_ip, "192.168.0.0/16") or incidr(action_remote_ip, "169.254.0.0/16") or incidr(action_remote_ip, "::1/128") or incidr(action_remote_ip, "fe80::/10") or incidr(action_remote_ip, "fc00::/7"))) or (incidr(action_remote_ip, "20.0.0.0/11")))))
