// Title: Registry Disable System Restore
// ID: 5de03871-5d46-4539-a82d-3aa992a69a83
// Status: test
// Level: high
// Author: frack113
// Date: 2022-04-04
// Tags: attack.impact, attack.t1490
// Description: Detects the modification of the registry to disable a system restore on the computer
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\Policies\\Microsoft\\Windows NT\\SystemRestore" or TargetObject contains "\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore") and (TargetObject endswith "DisableConfig" or TargetObject endswith "DisableSR") and Details = "DWORD (0x00000001)")
