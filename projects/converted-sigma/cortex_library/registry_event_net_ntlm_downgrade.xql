// Title: NetNTLM Downgrade Attack - Registry
// ID: d67572a0-e2ec-45d6-b8db-c100d14b8ef2
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), wagga, Nasreddine Bencherchali (Splunk STRT)
// Date: 2018-03-20
// Tags: attack.persistence, attack.defense-impairment, attack.t1685, attack.t1112
// Description: Detects NetNTLM downgrade attack
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "SYSTEM\\" and TargetObject contains "ControlSet" and TargetObject contains "\\Control\\Lsa")) and ((TargetObject endswith "\\lmcompatibilitylevel" and (Details = "DWORD (0x00000000)" or Details = "DWORD (0x00000001)" or Details = "DWORD (0x00000002)")) or (TargetObject endswith "\\NtlmMinClientSec" and (Details = "DWORD (0x00000000)" or Details = "DWORD (0x00000010)" or Details = "DWORD (0x00000020)" or Details = "DWORD (0x00000030)")) or (TargetObject endswith "\\RestrictSendingNTLMTraffic")))
