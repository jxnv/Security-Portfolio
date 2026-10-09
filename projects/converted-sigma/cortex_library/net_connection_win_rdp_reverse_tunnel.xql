// Title: RDP Over Reverse SSH Tunnel
// ID: 5f699bc5-5446-4a4a-a0b7-5ef2885a3eb4
// Status: test
// Level: high
// Author: Samir Bousseaden
// Date: 2019-02-16
// Tags: attack.command-and-control, attack.t1572, attack.lateral-movement, attack.t1021.001, car.2013-07-002
// Description: Detects svchost hosting RDP termsvcs communicating with the loopback address and on TCP port 3389
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "::1/128"))) and (action_process_image_path endswith "\\svchost.exe" and Initiated = "true" and action_local_port = 3389))
