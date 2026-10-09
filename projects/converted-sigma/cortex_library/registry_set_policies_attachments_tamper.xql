// Title: Potential Attachment Manager Settings Attachments Tamper
// ID: ee77a5db-b0f3-4be2-bfd4-b58be1c6b15a
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-01
// Tags: attack.defense-impairment
// Description: Detects tampering with attachment manager settings policies attachments (See reference for more information)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\") and ((TargetObject endswith "\\HideZoneInfoOnProperties" and Details = "DWORD (0x00000001)") or (TargetObject endswith "\\SaveZoneInformation" and Details = "DWORD (0x00000002)") or (TargetObject endswith "\\ScanWithAntiVirus" and Details = "DWORD (0x00000001)")))
