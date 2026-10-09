// Title: Terminal Server Client Connection History Cleared - Registry
// ID: 07bdd2f5-9c58-4f38-aec8-e101bb79ef8d
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-10-19
// Tags: attack.persistence, attack.stealth, attack.defense-impairment, attack.t1070, attack.t1112
// Description: Detects the deletion of registry keys containing the MSTSC connection history
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventType = "DeleteValue" and TargetObject contains "\\Microsoft\\Terminal Server Client\\Default\\MRU") or (EventType = "DeleteKey" and TargetObject contains "\\Microsoft\\Terminal Server Client\\Servers\\"))
