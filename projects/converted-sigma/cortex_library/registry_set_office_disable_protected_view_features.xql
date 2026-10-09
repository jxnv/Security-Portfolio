// Title: Microsoft Office Protected View Disabled
// ID: a5c7a43f-6009-4a8c-80c5-32abf1c53ecc
// Status: test
// Level: high
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-06-08
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects changes to Microsoft Office protected view registry keys with which the attacker disables this feature.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\SOFTWARE\\Microsoft\\Office\\" and TargetObject contains "\\Security\\ProtectedView\\")) and ((Details = "DWORD (0x00000000)" and (TargetObject endswith "\\enabledatabasefileprotectedview" or TargetObject endswith "\\enableforeigntextfileprotectedview")) or (Details = "DWORD (0x00000001)" and (TargetObject endswith "\\DisableAttachementsInPV" or TargetObject endswith "\\DisableInternetFilesInPV" or TargetObject endswith "\\DisableIntranetCheck" or TargetObject endswith "\\DisableUnsafeLocationsInPV"))))
