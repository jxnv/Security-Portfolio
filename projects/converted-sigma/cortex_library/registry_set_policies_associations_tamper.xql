// Title: Potential Attachment Manager Settings Associations Tamper
// ID: a9b6c011-ab69-4ddb-bc0a-c4f21c80ec47
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-01
// Tags: attack.defense-impairment
// Description: Detects tampering with attachment manager settings policies associations to lower the default file type risks (See reference for more information)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\\") and ((TargetObject endswith "\\DefaultFileTypeRisk" and Details = "DWORD (0x00006152)") or (TargetObject endswith "\\LowRiskFileTypes" and (Details contains ".zip;" or Details contains ".rar;" or Details contains ".exe;" or Details contains ".bat;" or Details contains ".com;" or Details contains ".cmd;" or Details contains ".reg;" or Details contains ".msi;" or Details contains ".htm;" or Details contains ".html;"))))
