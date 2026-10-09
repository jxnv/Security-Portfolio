// Title: Failed Logon From Public IP
// ID: f88e112a-21aa-44bd-9b01-6ee2a2bbbed1
// Status: test
// Level: medium
// Author: NVISO
// Date: 2020-05-06
// Tags: attack.privilege-escalation, attack.initial-access, attack.persistence, attack.stealth, attack.t1078, attack.t1190, attack.t1133
// Description: Detects a failed logon attempt from a public IP. A login from a public IP can indicate a misconfigured firewall or network boundary.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4625) and not (((IpAddress contains "-") or ((incidr(IpAddress, "::1/128") or incidr(IpAddress, "10.0.0.0/8") or incidr(IpAddress, "127.0.0.0/8") or incidr(IpAddress, "172.16.0.0/12") or incidr(IpAddress, "192.168.0.0/16") or incidr(IpAddress, "169.254.0.0/16") or incidr(IpAddress, "fc00::/7") or incidr(IpAddress, "fe80::/10"))))))
