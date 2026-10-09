// Title: New Firewall Rule Added In Windows Firewall Exception List Via WmiPrvSE.EXE
// ID: eca81e8d-09e1-4d04-8614-c91f44fd0519
// Status: test
// Level: medium
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-05-10
// Tags: attack.defense-impairment, attack.t1686.003
// Description: Detects the addition of a new "Allow" firewall rule by the WMI process (WmiPrvSE.EXE).
// This can occur if an attacker leverages PowerShell cmdlets such as "New-NetFirewallRule", or directly uses WMI CIM classes such as "MSFT_NetFirewallRule".
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 2004 or EventID = 2071 or EventID = 2097) and Action = 3 and ModifyingApplication endswith ":\\Windows\\System32\\wbem\\WmiPrvSE.exe")
