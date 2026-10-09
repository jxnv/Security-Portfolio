// Title: External Remote SMB Logon from Public IP
// ID: 78d5cab4-557e-454f-9fb9-a222bd0d5edc
// Status: test
// Level: high
// Author: Micah Babinski (@micahbabinski), Zach Mathis (@yamatosecurity)
// Date: 2023-01-19
// Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.credential-access, attack.stealth, attack.t1133, attack.t1078, attack.t1110
// Description: Detects successful logon from public IP address via SMB. This can indicate a publicly-exposed SMB port.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4624 and LogonType = 3) and not (((IpAddress = "-") or ((incidr(IpAddress, "::1/128") or incidr(IpAddress, "10.0.0.0/8") or incidr(IpAddress, "127.0.0.0/8") or incidr(IpAddress, "172.16.0.0/12") or incidr(IpAddress, "192.168.0.0/16") or incidr(IpAddress, "169.254.0.0/16") or incidr(IpAddress, "fc00::/7") or incidr(IpAddress, "fe80::/10"))))))
