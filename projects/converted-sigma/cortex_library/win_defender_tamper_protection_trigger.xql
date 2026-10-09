// Title: Microsoft Defender Tamper Protection Trigger
// ID: 49e5bc24-8b86-49f1-b743-535f332c2856
// Status: stable
// Level: high
// Author: Bhabesh Raj, Nasreddine Bencherchali
// Date: 2021-07-05
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects blocked attempts to change any of Defender's settings such as "Real Time Monitoring" and "Behavior Monitoring"
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 5013 and (Value endswith "\\Windows Defender\\DisableAntiSpyware" or Value endswith "\\Windows Defender\\DisableAntiVirus" or Value endswith "\\Windows Defender\\Scan\\DisableArchiveScanning" or Value endswith "\\Windows Defender\\Scan\\DisableScanningNetworkFiles" or Value endswith "\\Real-Time Protection\\DisableRealtimeMonitoring" or Value endswith "\\Real-Time Protection\\DisableBehaviorMonitoring" or Value endswith "\\Real-Time Protection\\DisableIOAVProtection" or Value endswith "\\Real-Time Protection\\DisableScriptScanning"))
