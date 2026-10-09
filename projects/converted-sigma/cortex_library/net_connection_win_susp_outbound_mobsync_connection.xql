// Title: Microsoft Sync Center Suspicious Network Connections
// ID: 9f2cc74d-78af-4eb2-bb64-9cd1d292b87b
// Status: test
// Level: medium
// Author: elhoim
// Date: 2022-04-28
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055, attack.t1218, attack.execution
// Description: Detects suspicious connections from Microsoft Sync Center to non-private IPs.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\mobsync.exe") and not (((incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "10.0.0.0/8") or incidr(action_remote_ip, "172.16.0.0/12") or incidr(action_remote_ip, "192.168.0.0/16") or incidr(action_remote_ip, "169.254.0.0/16") or incidr(action_remote_ip, "::1/128") or incidr(action_remote_ip, "fe80::/10") or incidr(action_remote_ip, "fc00::/7")))))
