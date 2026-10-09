// Title: Suspicious Shim Database Patching Activity
// ID: bf344fea-d947-4ef4-9192-34d008315d3a
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-08-01
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.011
// Description: Detects installation of new shim databases that try to patch sections of known processes for potential process injection or persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetObject contains "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\" and (TargetObject endswith "\\csrss.exe" or TargetObject endswith "\\dllhost.exe" or TargetObject endswith "\\explorer.exe" or TargetObject endswith "\\RuntimeBroker.exe" or TargetObject endswith "\\services.exe" or TargetObject endswith "\\sihost.exe" or TargetObject endswith "\\svchost.exe" or TargetObject endswith "\\taskhostw.exe" or TargetObject endswith "\\winlogon.exe" or TargetObject endswith "\\WmiPrvSe.exe"))
