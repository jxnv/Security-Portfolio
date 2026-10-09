// Title: Suspicious Shell Open Command Registry Modification
// ID: 9e8894c0-0ae0-11ef-9d85-1f2942bec57c
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-01-24
// Tags: attack.privilege-escalation, attack.persistence, attack.t1548.002, attack.t1546.001
// Description: Detects modifications to shell open registry keys that point to suspicious locations typically used by malware for persistence.
// Generally, modifications to the `*\shell\open\command` registry key can indicate an attempt to change the default action for opening files,
// and various UAC bypass or persistence techniques involve modifying these keys to execute malicious scripts or binaries.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetObject contains "\\shell\\open\\command\\" and (Details contains "\\$Recycle.Bin\\" or Details contains "\\AppData\\Local\\Temp\\" or Details contains "\\Contacts\\" or Details contains "\\Music\\" or Details contains "\\PerfLogs\\" or Details contains "\\Photos\\" or Details contains "\\Pictures\\" or Details contains "\\Users\\Public\\" or Details contains "\\Videos\\" or Details contains "\\Windows\\Temp\\" or Details contains "%AppData%" or Details contains "%LocalAppData%" or Details contains "%Temp%" or Details contains "%tmp%"))
